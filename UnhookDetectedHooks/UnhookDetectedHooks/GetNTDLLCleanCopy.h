#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <Psapi.h>  
#include <string>
#include <map>

constexpr SIZE_T STUB_SIZE = 16;
const BYTE NOP_PATTERN[8] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
const BYTE SYSCALL_OPCODE[2] = { 0x0F, 0x05 };

struct SyscallStubInfo {
    std::string functionName;
    SIZE_T stubOffset;
    SIZE_T nopOffset;
    SIZE_T nextStubOffset;
};

bool memcmp_bytes(const BYTE* a, const BYTE* b, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool contains_syscall(const BYTE* start, SIZE_T size) {
    // Check if the buffer contains the syscall opcode (0F 05)
    for (SIZE_T i = 0; i + 1 < size; i++) {
        if (start[i] == SYSCALL_OPCODE[0] && start[i + 1] == SYSCALL_OPCODE[1]) return true;
    }
    return false;
}

SIZE_T find_stub_offset(const BYTE* buffer, SIZE_T current, SIZE_T max_back = 16) {
    // Search backward up to max_back bytes to find the start of the syscall stub by pattern
    for (SIZE_T i = 0; i < max_back && current >= i + 2; i++) {
        if (buffer[current - i] == 0x4C && buffer[current - i + 1] == 0x8B && buffer[current - i + 2] == 0xD1)
            return current - i;
    }
    return current;
}

std::map<SIZE_T, std::string> load_exports_from_buffer(BYTE* buffer) {
    std::map<SIZE_T, std::string> exports;
    auto dosHeader = (IMAGE_DOS_HEADER*)buffer;
    auto ntHeaders = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) return exports;
    auto exportDir = (IMAGE_EXPORT_DIRECTORY*)(buffer + exportDirRVA);

    DWORD* namesRVA = (DWORD*)(buffer + exportDir->AddressOfNames);
    DWORD* funcsRVA = (DWORD*)(buffer + exportDir->AddressOfFunctions);
    WORD* ordinals = (WORD*)(buffer + exportDir->AddressOfNameOrdinals);

    // Load exported function RVAs and names into a map
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)(buffer + namesRVA[i]);
        WORD ordinal = ordinals[i];
        DWORD funcRVA = funcsRVA[ordinal];
        exports[funcRVA] = std::string(funcName);
    }
    return exports;
}

std::string find_function_name_by_rva(const std::map<SIZE_T, std::string>& exports, SIZE_T rva) {
    // Finds the closest function name for a given RVA by searching the exports map
    std::string lastName = "Unknown";
    for (const auto& it : exports) {
        SIZE_T addr = it.first;
        const std::string& name = it.second;
        if (addr > rva) break;
        lastName = name;
    }
    return lastName;
}

bool GetRemoteModuleInfo(HANDLE hProcess, const std::wstring& moduleName, BYTE*& baseAddress, SIZE_T& moduleSize) {
    // Get the base address and size of a module loaded in a remote process
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        std::cerr << "EnumProcessModulesEx failed with error: " << GetLastError() << "\n";
        return false;
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        wchar_t modName[MAX_PATH];
        if (GetModuleBaseNameW(hProcess, hMods[i], modName, sizeof(modName) / sizeof(wchar_t))) {
            if (_wcsicmp(modName, moduleName.c_str()) == 0) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    baseAddress = (BYTE*)modInfo.lpBaseOfDll;
                    moduleSize = modInfo.SizeOfImage;
                    return true;
                }
            }
        }
    }

    std::cerr << "Failed to find " << std::string(moduleName.begin(), moduleName.end()) << " in remote process\n";
    return false;
}

// The commented function below is an alternative way to get syscall stubs from the remote process directly by reading ntdll.dll memory there

/*
std::vector<SyscallStubInfo> GetSyscallStubs(HANDLE hProcess) {
    BYTE* remoteBase = nullptr;
    SIZE_T remoteSize = 0;
    if (!GetRemoteModuleInfo(hProcess, L"ntdll.dll", remoteBase, remoteSize)) {
        std::cerr << "Failed to find ntdll.dll in remote process\n";
        return std::vector<SyscallStubInfo>();
    }

    std::vector<BYTE> remoteImage(remoteSize);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, remoteBase, remoteImage.data(), remoteSize, &bytesRead) || bytesRead != remoteSize) {
        std::cerr << "Failed to read remote memory\n";
        return std::vector<SyscallStubInfo>();
    }

    auto exports = load_exports_from_buffer(remoteImage.data());
    std::vector<SyscallStubInfo> stubs;

    for (SIZE_T offset = 0; offset + STUB_SIZE <= remoteSize; offset++) {
        BYTE* stub_end = remoteImage.data() + offset + STUB_SIZE - sizeof(NOP_PATTERN);
        if (memcmp_bytes(stub_end, NOP_PATTERN, sizeof(NOP_PATTERN))) {
            BYTE* stub_raw = remoteImage.data() + offset;
            SIZE_T stub_off = find_stub_offset(remoteImage.data(), offset);
            if (contains_syscall(remoteImage.data() + stub_off, STUB_SIZE)) {
                SIZE_T corrected = (stub_off >= 16) ? stub_off - 16 : 0;
                std::string funcName = find_function_name_by_rva(exports, corrected);
                stubs.push_back({ funcName, corrected, offset + STUB_SIZE - sizeof(NOP_PATTERN), corrected + STUB_SIZE + 16 });
                offset += STUB_SIZE - 1;
            }
        }
    }

    for (const auto& s : stubs) {
        std::cout << "Syscall stub found:\n";
        std::cout << "  Function:            " << s.functionName << "\n";
        std::cout << "  Stub offset:         0x" << std::hex << s.stubOffset << "\n";
        std::cout << "  NOP offset:          0x" << std::hex << s.nopOffset << "\n";
        std::cout << "  Next stub offset:    0x" << std::hex << s.nextStubOffset << "\n\n";
    }

    CloseHandle(hProcess);
    return stubs;
}
*/

std::vector<SyscallStubInfo> GetSyscallStubs(HANDLE hProcess, std::vector<BYTE>* outCleanBuffer = nullptr) {
    // --- Get local ntdll.dll base address and size ---
    HMODULE hNtdllLocal = GetModuleHandle(L"ntdll.dll");
    if (!hNtdllLocal) {
        std::cerr << "Failed to get handle of ntdll.dll locally\n";
        return {};
    }

    MODULEINFO modInfoLocal = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hNtdllLocal, &modInfoLocal, sizeof(modInfoLocal))) {
        std::cerr << "Failed to get local module information\n";
        return {};
    }

    BYTE* localBase = reinterpret_cast<BYTE*>(modInfoLocal.lpBaseOfDll);
    SIZE_T moduleSize = modInfoLocal.SizeOfImage;

    std::cout << "Using local ntdll.dll base: " << static_cast<void*>(localBase)
        << ", size: " << moduleSize << " bytes\n";

    // --- Read remote memory at the local ntdll base (assuming base addresses match) ---
    std::vector<BYTE> remoteImage(moduleSize);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, localBase, remoteImage.data(), moduleSize, &bytesRead) || bytesRead != moduleSize) {
        std::cerr << "Failed to read remote process memory at local ntdll.dll base\n";
        return {};
    }

    // Save clean copy in the output parameter if requested
    if (outCleanBuffer) {
        *outCleanBuffer = remoteImage;
    }

    auto exports = load_exports_from_buffer(remoteImage.data());
    std::vector<SyscallStubInfo> stubs;

    for (SIZE_T offset = 0; offset + STUB_SIZE <= moduleSize; offset++) {
        BYTE* stub_end = remoteImage.data() + offset + STUB_SIZE - sizeof(NOP_PATTERN);
        if (memcmp_bytes(stub_end, NOP_PATTERN, sizeof(NOP_PATTERN))) {
            SIZE_T stub_off = find_stub_offset(remoteImage.data(), offset);
            if (contains_syscall(remoteImage.data() + stub_off, STUB_SIZE)) {
                SIZE_T corrected = (stub_off >= 16) ? stub_off - 16 : 0;
                std::string funcName = find_function_name_by_rva(exports, corrected);
                stubs.push_back({ funcName, corrected, offset + STUB_SIZE - sizeof(NOP_PATTERN), corrected + STUB_SIZE + 16 });
                offset += STUB_SIZE - 1;
            }
        }
    }

    for (const auto& s : stubs) {
        std::cout << "Syscall stub found:\n";
        std::cout << "  Function:            " << s.functionName << "\n";
        std::cout << "  Stub offset:         0x" << std::hex << s.stubOffset << "\n";
        std::cout << "  NOP offset:          0x" << std::hex << s.nopOffset << "\n";
        std::cout << "  Next stub offset:    0x" << std::hex << s.nextStubOffset << "\n\n";
    }

    return stubs;
}
