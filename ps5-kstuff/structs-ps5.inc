%define iret_rdi 0
%define iret_rsi 8
%define iret_rdx 16
%define iret_rcx 24
%define iret_r8 32
%define iret_r9 40
%define iret_rax 48
%define iret_rbx 56
%define iret_rbp 64
%define iret_r10 72
%define iret_r11 80
%define iret_r12 88
%define iret_r13 96
%define iret_r14 104
%define iret_r15 112
%define iret_rip 232
%define iret_cs (iret_rip+8)
%define iret_eflags (iret_rip+16)
%define iret_rsp (iret_rip+24)
%define iret_ss (iret_rip+32)

%define fpu_cr0_enter_stack_offset 512
%define fpu_cr0_exit_stack_offset 1024
%define fpu_cr0_exit_hook_ptr_offset 320
%define fpu_cr0_enter_hook_ptr_offset 328
%define fpu_cr0_scratch_offset 2048
%define fpu_cr0_cleared_offset (fpu_cr0_scratch_offset+8)
%define fpu_cr0_saved_offset (fpu_cr0_scratch_offset+0x58)
%define fpu_cr0_deferred_offset (fpu_cr0_scratch_offset+0x60)
%define trap_frame_extended_size (fpu_cr0_deferred_offset+8)
%define fpu_cr0_fast_enter_stack_offset 3072

%if 0
; TODO(FW_PORT): verify these kernel structure offsets in the new kernel
; thread/proc/PCB layouts.  Do not extend the version tests in uelf/utils.h
; until td_pcb, PCB base fields, and pcb_flags have been checked together.
%endif
%define td_proc 8
%define td_pcb 0x3f8
%define td_retval 0x408
%define td_frame 0x460

%define p_pid 0xbc

%define pcb_fsbase 0x40 //+10 10.0x
%define pcb_gsbase 0x48 //+10 10.0x
%define pcb_flags 0x100 //-38 2.70- +10 10.0x

%define sv_table 0x8

%if 0
; TODO(FW_PORT): derive these two values from the new syscall entry frame and
; validate both the normal syscall path and the register-stash continuation.
%endif
%define syscall_rsp_to_rsi 0x88 //+10 10.0x
%define syscall_rsp_to_regs_stash 0x110 //+10 10.0x

%if 0
; TODO(FW_PORT): verify the mailbox caller frame in the new kernel.  These are
; stack-ABI offsets, not stable structure members.
%endif
%define sceSblServiceMailbox_decryptSelfBlock_rsp_to_self_context 0x118
%define sceSblServiceMailbox_decryptSelfBlock_rsp_to_target_va 0x10
%define sceSblServiceMailbox_decryptSelfBlock_rsp_to_rbp 0x120

%if 0
; TODO(FW_PORT): obtain this size from the new mini-syscore SELF header used by
; sceSblAuthMgr; a wrong size overwrites adjacent kernel memory.
%endif
%define mini_syscore_header_size 0x6a0
