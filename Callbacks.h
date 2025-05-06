#include <windows.h>

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID* address;
    SIZE_T zeroBits;
    PSIZE_T size;
    ULONG allocationType;
    ULONG permissions;
    DWORD ssn;
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID address;
    PVOID buffer;
    ULONG numberOfBytesToWrite;
    PULONG numberOfBytesWritten;
    DWORD ssn;
} NTWRITEVIRTUALMEMORY_ARGS, * PNTWRITEVIRTUALMEMORY_ARGS;

typedef struct _NTCREATETHREADEX_ARGS {
    PHANDLE threadHandle;       
    ACCESS_MASK desiredAccess;   
    PVOID objectAttributes;     
    HANDLE processHandle;        
    PVOID lpStartAddress;        
    PVOID lpParameter;          
    ULONG flags;                
    SIZE_T stackZeroBits;        
    SIZE_T sizeOfStackCommit;    
    SIZE_T sizeOfStackReserve;   
    PVOID lpBytesBuffer;         
    DWORD ssn;                  
} NTCREATETHREADEX_ARGS, * PNTCREATETHREADEX_ARGS;


extern "C" void Search_For_Syscall_Ret(
    HANDLE ntdllHandle
);

extern "C" void Search_For_Add_Rsp_Ret(
    HANDLE ntdllHandle
);

extern "C" void NtAllocateVirtualMemory_Callback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work
);

extern "C" void NtWriteVirtualMemory_Callback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work
);

extern "C" void NtCreateThreadEx_Callback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work
);
