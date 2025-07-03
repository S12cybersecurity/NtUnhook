#include <iostream>
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include "DetectHooks.h"
#include "GetNTDLLCleanCopy.h"

using namespace std;

std::string normalize_function_name(const std::string& name) {
    if (name.size() > 2) {
        return name.substr(2); // Removes "Nt" or "Zw"
    }
    return name;
}

void RestoreHookedSyscalls(
    BYTE* localNtdllBase,
    const std::unordered_map<std::string, unsigned long>& hookedOffsets,
    const std::vector<SyscallStubInfo>& syscallStubs,
    SIZE_T moduleSize,
    BYTE* cleanBuffer)  // pointer to the clean buffer of ntdll.dll
{
    DWORD oldProtect = 0;

    for (std::unordered_map<std::string, unsigned long>::const_iterator it = hookedOffsets.begin(); it != hookedOffsets.end(); ++it) {
        const std::string& funcName = it->first;
        unsigned long hookedOffset = it->second;

        std::string normalizedHookName = normalize_function_name(funcName);

        // Search for corresponding clean stub ignoring the first two characters
        const SyscallStubInfo* cleanStub = NULL;
        for (size_t i = 0; i < syscallStubs.size(); ++i) {
            std::string normalizedStubName = normalize_function_name(syscallStubs[i].functionName);
            if (normalizedStubName == normalizedHookName) {
                cleanStub = &syscallStubs[i];
                break;
            }
        }

        if (!cleanStub) {
            std::cout << "[!] Clean stub not found for function: " << funcName << "\n";
            continue;
        }

        SIZE_T cleanStart = cleanStub->stubOffset;
        SIZE_T cleanEnd = cleanStub->nextStubOffset;
        if (cleanEnd <= cleanStart) {
            std::cout << "[!] Invalid stub offsets for function: " << funcName << "\n";
            continue;
        }
        SIZE_T cleanSize = cleanEnd - cleanStart;

        // Check that the range doesn't go beyond the module
        if (cleanStart + cleanSize > moduleSize) {
            std::cout << "[!] Stub range out of module bounds for: " << funcName << "\n";
            continue;
        }

        BYTE* targetAddr = localNtdllBase + hookedOffset;

        // Change memory protection
        if (!VirtualProtect(targetAddr, cleanSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "[!] VirtualProtect failed for function: " << funcName << " Error: " << GetLastError() << "\n";
            continue;
        }

        // Copy clean bytes from the local clean copy to the local ntdll
        memcpy(targetAddr, cleanBuffer + cleanStart, cleanSize);

        // Restore protection
        DWORD dummy = 0;
        VirtualProtect(targetAddr, cleanSize, oldProtect, &dummy);

        // Flush instruction cache
        FlushInstructionCache(GetCurrentProcess(), targetAddr, cleanSize);
        std::cout << "[+] Restored syscall stub: " << funcName << " at offset 0x" << std::hex << hookedOffset << "\n";
        getchar();
    }
}

HANDLE createBenignProcess()
{
    HANDLE hProcess = NULL;
    int result = 0;
    STARTUPINFOA startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    BOOL createSuccess = CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, "C:\\Windows\\System32\\", &startupInfo, &processInfo);

    if (createSuccess == FALSE) {
        cout << "[!] Error: Unable to invoke CreateProcess" << endl;
        return NULL;
    }
    return processInfo.hProcess;
}

int main()
{
    unordered_map<string, DWORD> hookedOffsets = GetHookedNtFunctionOffsets();
    // Added for debug purposes
    // hookedOffsets["NtCreateThread"] = 0;

    HANDLE hProcess = createBenignProcess();
    std::vector<BYTE> cleanBuffer;
    vector<SyscallStubInfo> syscallStubs = GetSyscallStubs(hProcess, &cleanBuffer);
    //hookedOffsets
    getchar();

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

    RestoreHookedSyscalls(localBase, hookedOffsets, syscallStubs, cleanBuffer.size(), cleanBuffer.data());
    return 0;
}
