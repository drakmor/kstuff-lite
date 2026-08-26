#include <errno.h>
#include <string.h>
#include "utils.h"
#include "log.h"
#include "npdrm.h"
#include "structs.h"
#include "traps.h"

static int copy_from_kernel_raw(void* dst, uint64_t src, uint64_t sz)
{
    char* p_dst = dst;
    while(sz)
    {
        uint64_t phys, phys_end;
        if(!virt2phys(src, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(p_dst, DMEM + phys, chk);
        p_dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

static int copy_to_kernel_raw(uint64_t dst, const void* src, uint64_t sz)
{
    const char* p_src = src;
    while(sz)
    {
        uint64_t phys, phys_end;
        if(!virt2phys(dst, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(DMEM + phys, p_src, chk);
        dst += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

__attribute__((noinline)) int virt2phys(uint64_t addr, uint64_t* phys,
                                       uint64_t* phys_limit)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(virt2phys_calls);
    uint64_t pml = cr3_phys;
    for(int i = 39; i >= 12; i -= 9)
    {
        if(pml >= ((1ull << 39) - (1ull << 12))) //dmem mapping size
        {
            METRIC_INC(virt2phys_failures);
            log_word(0xdead0000dead0000);
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 0;
        }
        uint64_t next_pml = *(uint64_t*)(DMEM + pml + ((addr & (0x1ffull << i)) >> (i - 3)));
        if(!(next_pml & 1))
        {
            METRIC_INC(virt2phys_failures);
            log_word(0xdeaddeaddeaddead);
            log_word((uint64_t)__builtin_return_address(0));
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 0;
        }
        if((next_pml & 128) || i == 12)
        {
            uint64_t addr1 = next_pml & ((1ull << 52) - (1ull << i));
            addr1 |= addr & ((1ull << i) - 1);
            *phys = addr1;
            *phys_limit = (addr1 | ((1ull << i) - 1)) + 1;
            METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
            return 1;
        }
        pml = next_pml & ((1ull << 52) - (1ull << 12));
    }
    METRIC_TIME(virt2phys_cycles_total, virt2phys_cycles_max, start_cycles);
    return 0;
}

int copy_from_kernel(void* dst, uint64_t src, uint64_t sz)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sz);
    if(copy_from_kernel_raw(dst, src, sz))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

int copy_to_kernel(uint64_t dst, const void* src, uint64_t sz)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sz);
    if(copy_to_kernel_raw(dst, src, sz))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
        return EFAULT;
    }
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

#if KSTUFF_OBS
#define METRIC_SCALAR_COPY_FROM_TIME(start) do { \
    uint64_t _metric_elapsed = uelf_rdtsc() - (uint64_t)(start); \
    METRIC_INC(scalar_copy_from_calls); \
    METRIC_ADD(copy_from_cycles_total, _metric_elapsed); \
    METRIC_MAX(copy_from_cycles_max, _metric_elapsed); \
    METRIC_ADD(scalar_copy_from_cycles_total, _metric_elapsed); \
    METRIC_MAX(scalar_copy_from_cycles_max, _metric_elapsed); \
} while(0)

#define METRIC_SCALAR_COPY_TO_TIME(start) do { \
    uint64_t _metric_elapsed = uelf_rdtsc() - (uint64_t)(start); \
    METRIC_INC(scalar_copy_to_calls); \
    METRIC_ADD(copy_to_cycles_total, _metric_elapsed); \
    METRIC_MAX(copy_to_cycles_max, _metric_elapsed); \
    METRIC_ADD(scalar_copy_to_cycles_total, _metric_elapsed); \
    METRIC_MAX(scalar_copy_to_cycles_max, _metric_elapsed); \
} while(0)
#else
#define METRIC_SCALAR_COPY_FROM_TIME(start) do { } while(0)
#define METRIC_SCALAR_COPY_TO_TIME(start) do { } while(0)
#endif

int copy_u16_from_kernel(uint16_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        __builtin_memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
    return 0;
}

int copy_u32_from_kernel(uint32_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        __builtin_memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
    return 0;
}

int copy_u64_from_kernel(uint64_t* dst, uint64_t src)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*dst));
    uint64_t phys, phys_end;
    if(!virt2phys(src, &phys, &phys_end))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(*dst))
        __builtin_memcpy(dst, DMEM + phys, sizeof(*dst));
    else if(copy_from_kernel_raw(dst, src, sizeof(*dst)))
    {
        METRIC_INC(copy_from_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_FROM_TIME(start_cycles);
    return 0;
}

int copy_u16_to_kernel(uint64_t dst, uint16_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        __builtin_memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_TO_TIME(start_cycles);
    return 0;
}

int copy_u32_to_kernel(uint64_t dst, uint32_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        __builtin_memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_TO_TIME(start_cycles);
    return 0;
}

int copy_u64_to_kernel(uint64_t dst, uint64_t value)
{
    METRIC_TIME_START(start_cycles);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, sizeof(value));
    uint64_t phys, phys_end;
    if(!virt2phys(dst, &phys, &phys_end))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    if(phys_end - phys >= sizeof(value))
        __builtin_memcpy(DMEM + phys, &value, sizeof(value));
    else if(copy_to_kernel_raw(dst, &value, sizeof(value)))
    {
        METRIC_INC(copy_to_failures);
        log_word((uint64_t)__builtin_return_address(0));
        METRIC_SCALAR_COPY_TO_TIME(start_cycles);
        return EFAULT;
    }
    METRIC_SCALAR_COPY_TO_TIME(start_cycles);
    return 0;
}

#undef METRIC_SCALAR_COPY_FROM_TIME
#undef METRIC_SCALAR_COPY_TO_TIME

uint64_t yield(void);

struct kernel_mapping_cache
{
    uint64_t physical_address;
    int valid;
#if KSTUFF_OBS
    uint64_t* hits;
    uint64_t* misses;
    uint64_t* fallbacks;
#endif
};

#if KSTUFF_OBS
#define DEFINE_MAPPING_CACHE(name, metric_prefix) \
    static struct kernel_mapping_cache name = { \
        .hits = &shared_area.metrics.metric_prefix##_hits, \
        .misses = &shared_area.metrics.metric_prefix##_misses, \
        .fallbacks = &shared_area.metrics.metric_prefix##_fallbacks, \
    }
#define OBSERVE_MAPPING_CACHE(cache, field) \
    __atomic_fetch_add((cache)->field, 1, __ATOMIC_RELAXED)
#else
#define DEFINE_MAPPING_CACHE(name, metric_prefix) \
    static struct kernel_mapping_cache name
#define OBSERVE_MAPPING_CACHE(cache, field) do { (void)(cache); } while(0)
#endif

DEFINE_MAPPING_CACHE(s_trap_frame_mapping, trap_mapping);
DEFINE_MAPPING_CACHE(s_just_return_mapping, just_return_mapping);
DEFINE_MAPPING_CACHE(s_pcpu_mapping, pcpu_mapping);
DEFINE_MAPPING_CACHE(s_tss_rsp0_mapping, tss_mapping);
DEFINE_MAPPING_CACHE(s_wrmsr_args_mapping, wrmsr_args_mapping);

#undef DEFINE_MAPPING_CACHE

extern char tss[];
extern uint64_t wrmsr_args;

/* These addresses belong to the per-CPU KELF and stay fixed for its lifetime. */
static __attribute__((noinline)) int initialize_kernel_mapping_cache(
    struct kernel_mapping_cache* cache, uint64_t address, uint64_t size,
    uint64_t* physical_address)
{
    uint64_t physical_limit;
    if(!virt2phys(address, physical_address, &physical_limit))
        return 0;
    if(*physical_address > physical_limit
    || size > physical_limit - *physical_address)
        return 0;

    cache->physical_address = *physical_address;
    __atomic_store_n(&cache->valid, 1, __ATOMIC_RELEASE);
    return 1;
}

static int get_cached_physical_address(struct kernel_mapping_cache* cache,
                                       uint64_t address, uint64_t size,
                                       uint64_t* physical_address)
{
    if(__atomic_load_n(&cache->valid, __ATOMIC_ACQUIRE))
    {
        OBSERVE_MAPPING_CACHE(cache, hits);
        *physical_address = cache->physical_address;
        return 1;
    }
    OBSERVE_MAPPING_CACHE(cache, misses);
    int initialized = initialize_kernel_mapping_cache(cache, address, size,
                                                      physical_address);
    if(!initialized)
        OBSERVE_MAPPING_CACHE(cache, fallbacks);
    return initialized;
}

#undef OBSERVE_MAPPING_CACHE

static __attribute__((noinline, cold)) int copy_from_kernel_uncached(
    void* dst, uint64_t src, uint64_t size)
{
    return copy_from_kernel(dst, src, size);
}

static __attribute__((noinline, cold)) int copy_to_kernel_uncached(
    uint64_t dst, const void* src, uint64_t size)
{
    return copy_to_kernel(dst, src, size);
}

static __attribute__((noinline)) int copy_from_cached_kernel_mapping(
    struct kernel_mapping_cache* cache, void* dst, uint64_t src,
    uint64_t mapping_size, uint64_t size)
{
    METRIC_TIME_START(start_cycles);
    uint64_t physical_address;
    if(size > mapping_size
    || !get_cached_physical_address(cache, src, mapping_size, &physical_address))
        return copy_from_kernel_uncached(dst, src, size);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, size);
    memcpy(dst, DMEM + physical_address, size);
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

static __attribute__((noinline)) int copy_to_cached_kernel_mapping(
    struct kernel_mapping_cache* cache, uint64_t dst, const void* src,
    uint64_t mapping_size, uint64_t size)
{
    METRIC_TIME_START(start_cycles);
    uint64_t physical_address;
    if(size > mapping_size
    || !get_cached_physical_address(cache, dst, mapping_size, &physical_address))
        return copy_to_kernel_uncached(dst, src, size);
    METRIC_INC(copy_to_calls);
    METRIC_ADD(copy_to_bytes, size);
    memcpy(DMEM + physical_address, src, size);
    METRIC_TIME(copy_to_cycles_total, copy_to_cycles_max, start_cycles);
    return 0;
}

static __attribute__((noinline)) int copy_u64_from_cached_kernel_mapping(
    struct kernel_mapping_cache* cache, uint64_t src, uint64_t* value)
{
    METRIC_TIME_START(start_cycles);
    uint64_t physical_address;
    if(!get_cached_physical_address(cache, src, sizeof(*value),
                                    &physical_address))
        return copy_u64_from_kernel(value, src);
    METRIC_INC(copy_from_calls);
    METRIC_ADD(copy_from_bytes, sizeof(*value));
    __builtin_memcpy(value, DMEM + physical_address, sizeof(*value));
    METRIC_TIME(copy_from_cycles_total, copy_from_cycles_max, start_cycles);
    return 0;
}

enum {
    TRAP_FRAME_MAPPING_SIZE = (NREGS + 1) * sizeof(uint64_t),
    JUST_RETURN_MAPPING_SIZE = 5 * sizeof(uint64_t),
};

__attribute__((noinline)) int copy_from_trap_frame_cached(void* dst, size_t size)
{
    return copy_from_cached_kernel_mapping(&s_trap_frame_mapping, dst,
                                           trap_frame, TRAP_FRAME_MAPPING_SIZE,
                                           size);
}

__attribute__((noinline)) int copy_to_trap_frame_cached(const void* src, size_t size)
{
    return copy_to_cached_kernel_mapping(&s_trap_frame_mapping, trap_frame,
                                         src, TRAP_FRAME_MAPPING_SIZE, size);
}

__attribute__((noinline)) int copy_from_just_return_cached(void* dst,
                                                          uint64_t just_return,
                                                          size_t size)
{
    return copy_from_cached_kernel_mapping(&s_just_return_mapping, dst,
                                           just_return, JUST_RETURN_MAPPING_SIZE,
                                           size);
}

__attribute__((noinline)) int copy_current_thread_from_pcpu_cached(uint64_t* td)
{
    return copy_u64_from_cached_kernel_mapping(&s_pcpu_mapping,
                                               (uint64_t)pcpu, td);
}

__attribute__((noinline)) int copy_rsp0_from_tss_cached(uint64_t* rsp0)
{
    return copy_u64_from_cached_kernel_mapping(&s_tss_rsp0_mapping,
                                               (uint64_t)tss + 4, rsp0);
}

__attribute__((noinline)) int copy_to_wrmsr_args_cached(const uint64_t args[3])
{
    return copy_to_cached_kernel_mapping(&s_wrmsr_args_mapping, wrmsr_args,
                                         args, 3 * sizeof(*args),
                                         3 * sizeof(*args));
}

__attribute__((noinline)) int run_gadget_checked(uint64_t* regs)
{
    METRIC_INC(run_gadget_calls);
    METRIC_TIME_START(start_cycles);
#define RETURN_RUN_GADGET(value) do { \
    int _run_gadget_result = (value); \
    if(_run_gadget_result) \
        METRIC_INC(run_gadget_failures); \
    METRIC_TIME(run_gadget_cycles_total, run_gadget_cycles_max, start_cycles); \
    return _run_gadget_result; \
} while(0)
    if(copy_to_trap_frame_cached(regs, NREGS*8))
        RETURN_RUN_GADGET(EFAULT);
    uint64_t just_return = yield();
    uint64_t jr_frame[5];
    if(copy_from_trap_frame_cached(regs, NREGS*8))
        RETURN_RUN_GADGET(EFAULT);
    if(copy_from_just_return_cached(jr_frame, just_return, sizeof(jr_frame)))
        RETURN_RUN_GADGET(EFAULT);
    regs[RDX] = jr_frame[2];
    regs[RCX] = jr_frame[3];
    regs[RAX] = jr_frame[4];
    RETURN_RUN_GADGET(0);
#undef RETURN_RUN_GADGET
}

extern char dr2gpr_start[];
extern char gpr2dr_1_start[];
extern char gpr2dr_2_start[];
extern char rdmsr_start[];
extern char rdmsr_end[];
extern char wrmsr_ret[];
extern char mov_rax_cr0[];
extern char mov_cr0_rax[];
extern char doreti_iret[];
extern char syscall_after[];

int read_dbgregs_checked(uint64_t* dr)
{
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)dr2gpr_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    if(run_gadget_checked(regs))
        return EFAULT;
    dr[0] = regs[R15];
    dr[1] = regs[R14];
    dr[2] = regs[R13];
    dr[3] = regs[R12];
    dr[4] = regs[R11];
    dr[5] = regs[RAX];
    return 0;
}

int write_dbgregs_checked(const uint64_t* dr)
{
    uint64_t regs[NREGS] = { [RIP] = (uint64_t)gpr2dr_1_start, 0x20, 2, 0, 0, [R8] = 0xdeadbeefdeadbeef };
    regs[R15] = dr[0];
    regs[R14] = dr[1];
    regs[R13] = dr[2];
    regs[RBX] = dr[3];
    regs[R11] = dr[4];
    regs[RCX] = dr[5];
    regs[RAX] = dr[5];
    if(run_gadget_checked(regs))
        return EFAULT;
    regs[R11] = dr[4];
    regs[R15] = dr[5];
    regs[R12] = 0xdeadbeefdeadbeef;
    regs[RIP] = (uint64_t)gpr2dr_2_start;
    return run_gadget_checked(regs);
}

int rdmsr(uint32_t which, uint64_t* ans)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)rdmsr_start, 0x20, 0x102, 0, 0,
        [RCX] = which,
    };
    if(run_gadget_checked(regs))
        return 0;
    if(regs[RIP] == (uint64_t)rdmsr_start)
        return 0;
    *ans = regs[RDX] << 32 | (uint32_t)regs[RAX];
    return 1;
}

int wrmsr(uint32_t which, uint64_t value)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)wrmsr_ret, 0x20, 0x102, 0, 0,
        [RCX] = which,
        [RAX] = (uint32_t)value,
        [RDX] = value >> 32,
    };
    if(run_gadget_checked(regs))
        return 0;
    return regs[RIP] != (uint64_t)wrmsr_ret;
}

int read_cr0_checked(uint64_t* cr0)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)mov_rax_cr0, 0x20, 0x102, 0, 0,
    };
    if(run_gadget_checked(regs))
        return EFAULT;
    *cr0 = regs[RAX];
    return 0;
}

int write_cr0_checked(uint64_t cr0)
{
    uint64_t regs[NREGS] = {
        [RIP] = (uint64_t)mov_cr0_rax, 0x20, 0x102, 0, 0,
        [RAX] = cr0,
    };
    return run_gadget_checked(regs);
}

void start_syscall_with_dbgregs(uint64_t* regs, const uint64_t* dbgregs)
{
    uint64_t stack_frame[12] = {
        (uint64_t)doreti_iret,
        MKTRAP(TRAP_UTILS, 1), 0, 0, 0, 0,
    };
    uint64_t p_pcb_flags;
    uint64_t pcb_flags_value;
    int had_dbregs;
    if(read_dbgregs_checked(stack_frame+6))
        return;
    if(get_current_pcb_flags_ptr_checked(&p_pcb_flags))
        return;
    if(get_pcb_dbregs_checked_at(p_pcb_flags, &pcb_flags_value, &had_dbregs))
        return;
    stack_frame[4] = had_dbregs;
    if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
        return;
    if(set_pcb_dbregs_checked_at(p_pcb_flags, pcb_flags_value))
        goto rollback_stack;
    if(write_dbgregs_checked(dbgregs))
    {
        restore_dbgregs_state_checked_at(p_pcb_flags, pcb_flags_value, stack_frame+6, had_dbregs);
rollback_stack:
        regs[RSP] += sizeof(stack_frame);
        return;
    }
}

void handle_utils_trap(uint64_t* regs, uint32_t trapno)
{
    if(trapno == 1)
    {
        enum { FRAME_QWORDS = 12, TAIL_OFFSET_QWORDS = 3 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        if(peek_stack_tail_checked(regs, tail,
                                   FRAME_QWORDS * sizeof(uint64_t),
                                   TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                   sizeof(tail)))
            return;
        if(restore_dbgregs_state_checked(tail+2, tail[0]))
            return;
        regs[RSP] += FRAME_QWORDS * sizeof(uint64_t);
        regs[RIP] = tail[8];
        finish_npdrm_ioctl_state();
        observe_current_syscall_finish();
    }
}
