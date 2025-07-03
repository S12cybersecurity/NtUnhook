#include <windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <iostream>
#include <unordered_map>
#include <string>

#pragma comment(lib, "Dbghelp.lib")

// Check if the given address contains a JMP instruction (used to detect hooks)
bool IsJmpInstruction(BYTE* addr) {
    return (addr[0] == 0xFF && addr[1] == 0x25) || (addr[0] == 0xE9) || (addr[0] == 0xEB);
}

// Returns a map of potentially hooked NTDLL functions and their RVA offsets
std::unordered_map<std::string, DWORD> GetHookedNtFunctionOffsets() {
    std::unordered_map<std::string, DWORD> hookedOffsets;

    // Get base address of ntdll.dll loaded in the current process
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return hookedOffsets;

    // Get export directory from ntdll
    ULONG exportDirSize;
    auto pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
        hNtdll, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportDirSize);

    if (!pExportDir) return hookedOffsets;

    // Resolve arrays of function RVAs, names, and ordinals
    DWORD* functionRVAs = (DWORD*)((BYTE*)hNtdll + pExportDir->AddressOfFunctions);
    DWORD* nameRVAs = (DWORD*)((BYTE*)hNtdll + pExportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hNtdll + pExportDir->AddressOfNameOrdinals);

    // Iterate over all exported names
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)hNtdll + nameRVAs[i];

        // Skip non-syscall functions (only process "Nt" or "Zw" functions)
        if (strncmp(functionName, "Nt", 2) != 0 && strncmp(functionName, "Zw", 2) != 0)
            continue;

        // Skip internal functions like "NtdllDialogWndProc"
        if (strncmp(functionName, "Ntdll", 5) == 0)
            continue;

        // Get function address via ordinal table
        DWORD funcRVA = functionRVAs[ordinals[i]];
        BYTE* functionAddress = (BYTE*)hNtdll + funcRVA;

        // Check if the function starts with a jump instruction (possible hook)
        if (IsJmpInstruction(functionAddress)) {
            // Save the RVA of the potentially hooked function
            hookedOffsets[functionName] = funcRVA;
            std::cout << "Function " << functionName
                << " at RVA 0x" << std::hex << funcRVA
                << " Address " << static_cast<void*>(functionAddress) << std::endl;
        }
    }

    return hookedOffsets;
}
