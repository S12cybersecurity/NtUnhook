# SelectiveIn-MemoryNTDLLUnhooking

**Selective In-Memory Syscall Unhooking** is a stealthy method to bypass user-mode hooks in `ntdll.dll` by selectively restoring genuine syscall stubs from a clean copy of `ntdll.dll` loaded in a suspended child process. This approach avoids disk I/O, preserves process stability, and improves stealth against EDR/AV hooks.

---

## Overview

Modern Endpoint Detection and Response (EDR) and Antivirus (AV) solutions often hook native API functions in `ntdll.dll` to monitor system calls. Common bypass techniques either rely on hardcoded syscall numbers (which vary by OS version) or loading clean DLLs from disk (which triggers file access alerts).

This tool uses a fileless technique that:

- Spawns a suspended child process (e.g., `cmd.exe`) to load an unhooked `ntdll.dll` in memory.
- Reads the clean `ntdll.dll` image from the suspended process memory.
- Parses export functions beginning with "Nt" to locate syscall stubs.
- Selectively overwrites hooked syscall stubs in the current process’s `ntdll.dll` with clean stubs.
- Avoids touching disk or overwriting entire DLLs, preserving stability and evading detection.

---

## Features

- **Fileless unhooking**: No disk I/O involved; all operations occur in memory.
- **Selective restoration**: Only syscall stubs that are hooked are restored, minimizing memory changes.
- **Process stability**: Avoids overwriting full DLLs, reducing risk of crashes or incompatibilities.
- **Stealthy**: Bypasses common user-mode hook techniques used by EDR/AV solutions.
- **Cross-version compatible**: Works across Windows versions by reading clean syscall stubs dynamically.

---

## How It Works

1. **Spawn Suspended Process**  
   Launch a child process in suspended mode (e.g., `cmd.exe`). This process loads a clean, unhooked `ntdll.dll`.

2. **Read Clean NTDLL Image**  
   Locate the base address of `ntdll.dll` in the suspended child and read its full image into a local buffer using `ReadProcessMemory`.

3. **Parse Export Table**  
   Extract exported function names and addresses from both the clean buffer and current process `ntdll.dll`. Focus on native API functions starting with `"Nt"`.

4. **Identify Syscall Stubs**  
   Find the 23-byte syscall prologue pattern in the clean image (e.g., `mov r10, rcx; mov eax, imm; syscall; ret`).

5. **Remap Hooked Functions**  
   Using the matching relative virtual addresses (RVAs), overwrite hooked syscall stubs in the current process with the clean bytes. Memory protection is adjusted dynamically for writing.

6. **Cleanup**  
   Terminate the suspended process. The current process now has restored, genuine syscall stubs.

---

## Comparison With Other Techniques

| Technique          | Disk I/O | Stability     | Stealth       | Environment Dependency |
|--------------------|----------|---------------|---------------|-----------------------|
| Load clean DLL disk | Yes      | Medium        | Low (file ops) | None                  |
| Hell’s Gate        | No       | Medium        | Medium        | Assumes intact stubs   |
| Heaven’s Gate      | No       | Medium        | Medium        | Requires WoW64 (32-bit host) |
| Perun’s Fart       | No       | Medium-High   | High          | Requires suspended process |
| **SelectiveIn-MemoryNTDLLUnhooking** | No       | High          | Very High    | Requires suspended process |

---

## Usage

- Compile the provided C++ example.
- The tool automatically spawns a suspended process, extracts clean stubs, and patches current `ntdll.dll`.

---

## Requirements

- Windows OS with `ntdll.dll`.
- Access rights to spawn suspended processes and read process memory.
- Compatible with x64 Windows processes.

---

## License

This tool and code samples are provided for educational and ethical red teaming purposes only.

---

## References

- [dosxuz's blog on syscall unhooking](https://dosxuz.gitlab.io)
- [Cymulate EDR analysis](https://cymulate.com)
- [Hell’s Gate and Heaven’s Gate techniques on GitHub](https://github.com)
- [Perun’s Fart syscall unhooking technique](https://dosxuz.gitlab.io)

---

## Author

Developed by 0x12 Dark Development  
Red Team / Malware Developer

---

Feel free to open issues or contribute improvements.

