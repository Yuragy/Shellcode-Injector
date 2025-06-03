# Shellcode Injector

A proof-of-concept **shellcode injector** that uses *clean syscalls* to bypass user-mode hooks in **`ntdll.dll`**.

## 🎯 Goals

- **Activity obfuscation**  
- Inject shellcode into a target process via **raw syscalls** (ret stubs from `ntdll.dll`)  
- **Bypass** common user-mode hooks on Win32 APIs (`LoadLibrary`, `VirtualAlloc`, `WriteProcessMemory`, …)  
- **Auto-generate** & embed a shellcode payload that **downloads and executes a PE file**  

---

## 🛠️ How It Works

1. Leverages the **Windows Thread Pool API** to *hide the call-stack*:  
   - The syscall appears to originate from a *trusted* region inside **`ntdll!TpWorker`** rather than from our code.  
2. No direct native API calls are made; instead, the injector **jumps to syscall stubs** discovered in `ntdll.dll`.

---

## 📁 Project Files

| Path | Purpose |
|------|---------|
| `include/PEB.h` | Struct definitions for **PEB / TEB / LDR_MODULE** |
| `include/Callbacks.h` | Prototypes & argument structs for the three syscalls |
| `Callbacks.asm` | NASM routines: locate raw syscall stubs → unpack args → `syscall; ret` |
| `Shellcode.h.template` | DSL (Intel syntax) between `SHELLCODE_START / END` markers |
| `generate_shellcode_header.py` | Assembles the DSL → overwrites **`Shellcode.h`** with a byte array |
| `main.cpp` | C++ wrapper: `EnableDebugPrivilege`, SSN lookup, Thread Pool callbacks, wrappers for<br>`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` |
| `Makefile` | Automation: <br>1️⃣ Generate `Shellcode.h`<br>2️⃣ Assemble ASM routines<br>3️⃣ Compile & link → **`injector.exe`** |

---

## ⚙️ Technologies & Dependencies

- **Windows x64** – MSVC / Visual Studio Build Tools  
- **NASM** `-f win64`  
- **Python 3.x** + **Keystone-engine**  
  ```bash
  pip install keystone-engine


---

## 🚀 Build & Run

```bash
# 1) Install NASM, MSVC, Python + Keystone beforehand

# 2) Generate Shellcode.h from the template
python generate_shellcode_header.py Shellcode.h.template Shellcode.h

# 3) Build everything
make

# 4) Launch the injector
injector.exe
```

---

## 🚫 Disclaimer

This repository is provided for **educational purposes only** and intended for **authorized security research**.
Use of these materials in unauthorized or illegal activities is **strictly prohibited**.


