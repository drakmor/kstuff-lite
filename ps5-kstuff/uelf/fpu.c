#include "utils.h"
#include "shared_area.h"

enum {
    XSAVE_AREA_SIZE = 4096,
    XSAVE_MIN_AREA_SIZE = 512 + 64,
    XSAVE_MODE_UNINITIALIZED = 0,
    XSAVE_MODE_XSAVE = 1,
    XSAVE_MODE_XSAVEC = 2,
    XSAVE_MODE_UNUSABLE = 3,
};

__attribute__((aligned(64))) static char xsave_area[XSAVE_AREA_SIZE];
static uint32_t xsave_eax, xsave_edx;
static uint32_t xsave_mode;
static uint64_t saved_cr0;
static uint64_t pending_cr0;
static uint32_t fpu_depth;
static uint32_t fpu_state_saved;
static uint32_t cr0_restore_pending;

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t* eax,
                  uint32_t* ebx, uint32_t* ecx, uint32_t* edx)
{
    uint32_t a, b, c, d;
    asm volatile("cpuid"
                 : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                 : "a"(leaf), "c"(subleaf));
    *eax = a;
    *ebx = b;
    *ecx = c;
    *edx = d;
}

static int xsave_mode_usable(uint32_t mode)
{
    return mode == XSAVE_MODE_XSAVE || mode == XSAVE_MODE_XSAVEC;
}

static int initialize_xsave_mode(void)
{
    uint32_t mode = __atomic_load_n(&xsave_mode, __ATOMIC_ACQUIRE);
    if(mode != XSAVE_MODE_UNINITIALIZED)
        return xsave_mode_usable(mode) ? 0 : 1;

    uint32_t eax, ebx, ecx, edx;
    uint32_t xsave_size = 0;
    uint64_t xcr0 = 0;

    cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    uint32_t max_basic_leaf = eax;
    if(max_basic_leaf < 1)
    {
        mode = XSAVE_MODE_UNUSABLE;
        goto done;
    }

    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if(max_basic_leaf < 0x0d
    || !(ecx & (1u << 26))
    || !(ecx & (1u << 27)))
    {
        mode = XSAVE_MODE_UNUSABLE;
        goto done;
    }

    asm volatile("xgetbv":"=d"(xsave_edx),"=a"(xsave_eax):"c"(0));
    xcr0 = (uint64_t)xsave_edx << 32 | xsave_eax;

    /* D.0:EBX is the size required by the currently enabled XCR0 state. */
    cpuid(0x0d, 0, &eax, &ebx, &ecx, &edx);
    uint64_t supported_xcr0 = (uint64_t)edx << 32 | eax;
    xsave_size = ebx;
    uint32_t max_xsave_size = ecx;

    /* D.1:EAX[1] advertises compacted XSAVEC/XRSTOR state. */
    uint32_t cpuid_d1_eax;
    cpuid(0x0d, 1, &cpuid_d1_eax, &ebx, &ecx, &edx);

    if((xcr0 & 3) != 3 || (xcr0 & ~supported_xcr0))
        mode = XSAVE_MODE_UNUSABLE;
    else if(xsave_size < XSAVE_MIN_AREA_SIZE || xsave_size > max_xsave_size)
        mode = XSAVE_MODE_UNUSABLE;
    else if(xsave_size > sizeof(xsave_area))
        mode = XSAVE_MODE_UNUSABLE;
    else if(cpuid_d1_eax & (1u << 1))
        mode = XSAVE_MODE_XSAVEC;
    else
        mode = XSAVE_MODE_XSAVE;

done:
    __atomic_store_n(&xsave_mode, mode, __ATOMIC_RELEASE);
    METRIC_INC(fpu_xcr0_initializations);
    return xsave_mode_usable(mode) ? 0 : 1;
}

static void save_fpu_state(void)
{
    METRIC_TIME_START(start_cycles);
    if(xsave_mode == XSAVE_MODE_XSAVEC)
    {
        /*
         * Do not use XSAVEOPT with this per-CPU scratch area.  XSAVEOPT may
         * omit a component which was not modified since the kernel's last
         * XRSTOR, relying on the destination being that same owner's prior
         * save area.  XSAVEC has no such same-buffer requirement and XRSTOR
         * understands its compacted header.
         */
        asm volatile("xsavec %0":"=m"(xsave_area)
                     :"a"(xsave_eax),"d"(xsave_edx));
        METRIC_INC(fpu_xsavec_calls);
    }
    else
    {
        asm volatile("xsave %0":"=m"(xsave_area)
                     :"a"(xsave_eax),"d"(xsave_edx));
        METRIC_INC(fpu_xsave_calls);
    }
    METRIC_TIME(fpu_xsave_cycles_total, fpu_xsave_cycles_max, start_cycles);
}

static void restore_fpu_state(void)
{
    METRIC_TIME_START(start_cycles);
    asm volatile("xrstor %0"::"m"(xsave_area),
                 "a"(xsave_eax),"d"(xsave_edx));
    METRIC_TIME(fpu_xrstor_cycles_total, fpu_xrstor_cycles_max, start_cycles);
}

int uelf_fpu_enter(void)
{
    if(fpu_depth++)
    {
        METRIC_INC(fpu_nested_enters);
        return 0;
    }
    METRIC_INC(fpu_enters);
    METRIC_TIME_START(start_cycles);
    fpu_state_saved = 0;
    if(initialize_xsave_mode())
    {
        METRIC_INC(fpu_enter_failures);
        fpu_depth = 0;
        METRIC_TIME(fpu_enter_cycles_total, fpu_enter_cycles_max,
                    start_cycles);
        return 1;
    }
    if(read_cr0_clear_ts_checked(&saved_cr0))
    {
        METRIC_INC(fpu_enter_failures);
        fpu_depth = 0;
        METRIC_TIME(fpu_enter_cycles_total, fpu_enter_cycles_max,
                    start_cycles);
        return 1;
    }
    save_fpu_state();
    asm volatile("finit");
    uint32_t mxcsr = 0x1f80;
    asm volatile("ldmxcsr %0"::"m"(mxcsr));
    fpu_state_saved = 1;
    METRIC_TIME(fpu_enter_cycles_total, fpu_enter_cycles_max, start_cycles);
    return 0;
}

void uelf_fpu_exit(void)
{
    if(!fpu_depth)
        return;
    if(--fpu_depth)
        return;
    if(!fpu_state_saved)
        return;
    METRIC_INC(fpu_exits);
    METRIC_TIME_START(start_cycles);
    restore_fpu_state();
    if((saved_cr0 & 8) && !cr0_restore_pending)
    {
        pending_cr0 = saved_cr0;
        cr0_restore_pending = 1;
    }
    fpu_state_saved = 0;
    METRIC_TIME(fpu_exit_cycles_total, fpu_exit_cycles_max, start_cycles);
}

/* Called by crt.asm immediately before the terminal HLT, after all yields. */
void uelf_fpu_finish(void)
{
    if(!cr0_restore_pending)
        return;
    uint64_t cr0 = pending_cr0;
    cr0_restore_pending = 0;
    if(defer_cr0_restore_checked(cr0))
        METRIC_INC(fpu_exit_failures);
}
