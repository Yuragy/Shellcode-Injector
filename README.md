# asmLoader  
A PoC shellcode injector using clean syscalls to bypass user-mode hooks in ntdll.dll.

### Goals
- Activity obfuscation  
- Demonstrate injecting shellcode into a process via raw syscall; ret stubs from ntdll.dll  
- Bypass user-mode hooks on Win32 APIs (LoadLibrary, VirtualAlloc, WriteProcessMemory)  
- Automatically generate and insert a shellcode payload to download and execute a PE file  

### How It Works
- Uses the Windows Thread Pool API to “hide” the call stack: instead of a direct syscall from code, the call originates from a trusted region inside ntdll tpWorker.  
- No direct native API calls are made—instead, jmp to a syscall stub found in ntdll.

### Project Files
- include/PEB.h — Definitions for PEB/TEB structures, LDR_MODULE  
- include/Callbacks.h — Prototypes for callbacks and argument structs for three syscalls  
- Callbacks.asm — NASM routines: locate raw syscall stubs and unpack arguments → syscall; ret  
- Shellcode.h.template — DSL (Intel syntax) between SHELLCODE_START/SHELLCODE_END markers  
- generate_shellcode_header.py — Assembles the DSL from the template and overwrites Shellcode.h with a byte array  
- main.cpp — C++ wrapper EnableDebugPrivilege, SSN lookup, ThreadPool callbacks, wrappers for NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx  
- Makefile — Automation for:  
  1. Generating Shellcode.h  
  2. Assembling ASM routines  
  3. Compiling and linking into injector.exe

### Technologies & Dependencies
- Windows x64 MSVC / Visual Studio Build Tools 
- NASM -f win64  
- Python 3.x + keystone-engine  
  pip install keystone-engine

### Build & Run

1. Install dependencies NASM, MSVC, Python + Keystone 
2. Generate Shellcode.h from the template:
   python generate_shellcode_header.py Shellcode.h.template Shellcode.h
3. Build the project:
   make
4. Run the injector:
   injector.exe

## This is just a demonstration of a training manual for malware researchers