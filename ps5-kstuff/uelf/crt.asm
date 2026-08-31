section .text
use64

global yield
global memcpy
global memset
global memmove
global cr3_phys
global trap_frame
global wrmsr_args
global _start
extern main
extern uelf_fpu_finish

yield:
push rbp
push rbx
push r12
push r13
push r14
push r15
mov [rel saved_rsp], rsp
hlt

memcpy:
mov rax, rdi
mov rcx, rdx
rep movsb
ret

memset:
movzx eax, sil
mov rsi, rdi
mov rcx, rdx
rep stosb
mov rax, rsi
ret

memmove:
mov rax, rdi
sub rax, rsi
cmp rax, rdx
jae memcpy
test rax, rax
je .mov_rax_rdi_ret
lea rdi, [rdi+rdx-1]
lea rsi, [rsi+rdx-1]
mov rcx, rdx
std
rep movsb
cld
inc rdi
.mov_rax_rdi_ret:
mov rax, rdi
ret

; rdi = trap_frame
; rsi = cr3 of caller
; rdx = our cr3 (currently unused)
; rcx = justreturn frame (has saved rax/rcx/rdx)
_start:
mov [rel trap_frame], rdi
mov [rel cr3_phys], rsi
mov [rel wrmsr_args], r8
xor rsp, rsp
xchg rsp, [rel saved_rsp]
test rsp, rsp
jnz .unyield
lea rsp, [rel stack_end]
mov rdi, rcx
mov rsi, r8
call main
call uelf_fpu_finish
hlt
.unyield:
mov rax, rcx
pop r15
pop r14
pop r13
pop r12
pop rbx
pop rbp
ret

section .bss
align 16
trap_frame:
resq 1
cr3_phys:
resq 1
wrmsr_args:
resq 1
stack:
resb 16384
align 16
stack_end:
saved_rsp:
dq 0
