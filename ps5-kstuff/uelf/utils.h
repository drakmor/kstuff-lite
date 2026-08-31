#pragma once
#include <sys/types.h>
#include <stddef.h>
#include "structs.h"
#include "log.h"

extern uint64_t cr3_phys;
extern uint64_t trap_frame;
extern char pcpu[];
extern char fwver[];

struct dbgregs_snapshot
{
    uint64_t dr[6];
    uint64_t p_pcb_flags;
    uint32_t flags_value;
    int had_dbregs;
};

_Static_assert(sizeof(struct dbgregs_snapshot) == 64,
               "unexpected debug-register snapshot size");

extern char dmem[];
#define DMEM dmem
#define FWVER ((uint64_t)(uintptr_t)fwver)

int virt2phys(uint64_t addr, uint64_t* phys, uint64_t* phys_limit);
int copy_from_kernel(void* dst, uint64_t src, uint64_t sz);
int copy_to_kernel(uint64_t dst, const void* src, uint64_t sz);
int copy_u16_from_kernel(uint16_t* dst, uint64_t src);
int copy_u32_from_kernel(uint32_t* dst, uint64_t src);
int copy_u64_from_kernel(uint64_t* dst, uint64_t src);
int copy_u16_to_kernel(uint64_t dst, uint16_t value);
int copy_u32_to_kernel(uint64_t dst, uint32_t value);
int copy_u64_to_kernel(uint64_t dst, uint64_t value);
int copy_from_trap_frame_cached(void* dst, size_t size);
int copy_to_trap_frame_cached(const void* src, size_t size);
int copy_from_just_return_cached(void* dst, uint64_t just_return, size_t size);
int copy_current_thread_from_pcpu_cached(uint64_t* td);
int copy_rsp0_from_tss_cached(uint64_t* rsp0);
int copy_to_wrmsr_args_cached(const uint64_t args[3]);
int run_gadget_checked(uint64_t* regs);
int read_dbgregs_checked(uint64_t* dr);
int write_dbgregs_checked(const uint64_t* dr);
int snapshot_current_dbgregs_checked(struct dbgregs_snapshot* snapshot);
int install_dbgregs_checked(const uint64_t* dr,
                            const struct dbgregs_snapshot* snapshot);
int read_cr0_checked(uint64_t* cr0);
int read_cr0_clear_ts_checked(uint64_t* cr0);
int write_cr0_checked(uint64_t cr0);
int defer_cr0_restore_checked(uint64_t cr0);
void start_syscall_with_dbgregs(uint64_t* regs, const uint64_t* dbgregs);
void handle_utils_trap(uint64_t* regs, uint32_t trapno);
void handle_syscall(uint64_t* regs, int allow_kekcall);
int rdmsr(uint32_t which, uint64_t* ans);
int wrmsr(uint32_t which, uint64_t value);

static inline uint64_t uelf_rdtsc(void)
{
    uint32_t eax, edx;
    asm volatile("rdtsc":"=a"(eax),"=d"(edx)::"memory");
    return (uint64_t)edx << 32 | eax;
}

#if KSTUFF_OBS
#define METRIC_TIME_START(var) uint64_t var = uelf_rdtsc()
#define METRIC_TIME(total_field, max_field, start_cycles) do { \
    uint64_t _metric_elapsed = uelf_rdtsc() - (uint64_t)(start_cycles); \
    METRIC_ADD(total_field, _metric_elapsed); \
    METRIC_MAX(max_field, _metric_elapsed); \
} while(0)
#else
#define METRIC_TIME_START(var) enum { var = 0 }
#define METRIC_TIME(total_field, max_field, start_cycles) do { } while(0)
#endif

static inline int kpeek64_checked(uintptr_t kptr, uint64_t* value)
{
    return copy_u64_from_kernel(value, kptr);
}

static inline uint64_t kpeek64(uintptr_t kptr)
{
    uint64_t ans = 0;
    if(kpeek64_checked(kptr, &ans))
        log_word((uint64_t)__builtin_return_address(0));
    return ans;
}

static inline void kpoke64(uintptr_t kptr, uint64_t value)
{
    copy_u64_to_kernel(kptr, value);
}

static inline int push_stack_checked(uint64_t* regs, const void* data, size_t sz)
{
    uint64_t rsp = regs[RSP] - sz;
    if(copy_to_kernel(rsp, data, sz))
        return 1;
    regs[RSP] = rsp;
    return 0;
}

static inline int pop_stack_checked(uint64_t* regs, void* data, size_t sz)
{
    if(copy_from_kernel(data, regs[RSP], sz))
        return 1;
    regs[RSP] += sz;
    return 0;
}

static inline int peek_stack_checked(const uint64_t* regs, void* data, size_t sz)
{
    return copy_from_kernel(data, regs[RSP], sz);
}

static inline int peek_stack_tail_checked(const uint64_t* regs, void* data,
                                          size_t frame_sz, size_t tail_offset,
                                          size_t tail_sz)
{
    if(tail_offset > frame_sz || tail_sz > frame_sz - tail_offset)
        return 1;
    return copy_from_kernel(data, regs[RSP] + tail_offset, tail_sz);
}

static inline int pop_stack_tail_checked(uint64_t* regs, void* data,
                                         size_t frame_sz, size_t tail_offset,
                                         size_t tail_sz)
{
    if(peek_stack_tail_checked(regs, data, frame_sz, tail_offset, tail_sz))
        return 1;
    regs[RSP] += frame_sz;
    return 0;
}

static inline uint64_t get_pcb_field_ptr(uint64_t pcb, uint64_t field_offset)
{
    /*
     * TODO(FW_PORT): verify the PCB insertion introduced at 10.00 and update
     * this rule only after checking pcb_fsbase, pcb_gsbase, pcb_flags and the
     * debug-register save area in the new kernel's cpu_switch code.
     */
    return pcb + field_offset + (FWVER >= 0x1000 ? 0x10 : 0);
}

static inline int get_thread_pcb_checked(uint64_t td, uint64_t* pcb)
{
    return kpeek64_checked(td + td_pcb, pcb);
}

static inline int get_current_pcb_checked(uint64_t* pcb)
{
    uint64_t td;
    if(copy_current_thread_from_pcpu_cached(&td))
        return 1;
    return get_thread_pcb_checked(td, pcb);
}

static inline int get_current_pcb_flags_ptr_checked(uint64_t* p_pcb_flags)
{
    uint64_t pcb;
    if(get_current_pcb_checked(&pcb))
        return 1;

    *p_pcb_flags = get_pcb_field_ptr(
        pcb,
        pcb_flags - (FWVER <= 0x270 ? 0x38 : 0)
    );

    return 0;
}

static inline int get_pcb_dbregs_checked(int* enabled)
{
    uint32_t flags;
    uint64_t p_pcb_flags;
    if(get_current_pcb_flags_ptr_checked(&p_pcb_flags))
        return 1;
    if(copy_u32_from_kernel(&flags, p_pcb_flags))
        return 1;
    *enabled = !!(flags & PCB_DBREGS);
    return 0;
}

static inline int get_pcb_dbregs_checked_at(uint64_t p_pcb_flags, uint32_t* flags, int* enabled)
{
    if(copy_u32_from_kernel(flags, p_pcb_flags))
        return 1;
    *enabled = !!(*flags & PCB_DBREGS);
    return 0;
}

static inline int set_pcb_dbregs_checked_at(uint64_t p_pcb_flags, uint32_t flags)
{
    return copy_u32_to_kernel(p_pcb_flags, flags | PCB_DBREGS);
}

static inline int clear_pcb_dbregs_checked(void)
{
    uint64_t p_pcb_flags;
    uint32_t flags;
    if(get_current_pcb_flags_ptr_checked(&p_pcb_flags))
        return 1;
    if(copy_u32_from_kernel(&flags, p_pcb_flags))
        return 1;
    return copy_u32_to_kernel(p_pcb_flags, flags & ~PCB_DBREGS);
}

static inline int clear_pcb_dbregs_checked_at(uint64_t p_pcb_flags, uint32_t flags)
{
    return copy_u32_to_kernel(p_pcb_flags, flags & ~PCB_DBREGS);
}

static inline int restore_dbgregs_state_checked(const uint64_t* dr, int had_dbregs)
{
    if(write_dbgregs_checked(dr))
        return 1;
    if(!had_dbregs && clear_pcb_dbregs_checked())
        return 1;
    return 0;
}

static inline int restore_dbgregs_state_checked_at(uint64_t p_pcb_flags, uint32_t flags, const uint64_t* dr, int had_dbregs)
{
    if(write_dbgregs_checked(dr))
        return 1;
    if(!had_dbregs && clear_pcb_dbregs_checked_at(p_pcb_flags, flags))
        return 1;
    return 0;
}
