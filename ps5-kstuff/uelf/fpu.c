#include "utils.h"
#include "shared_area.h"

__attribute__((aligned(64))) static char xsave_area[4096]; //is this enough?
static uint32_t xsave_eax, xsave_edx;
static uint32_t xsave_mode_initialized;
static uint32_t xsavec_supported;
static uint64_t saved_cr0;
static uint64_t pending_cr0;
static uint32_t fpu_depth;
static uint32_t fpu_state_saved;
static uint32_t cr0_restore_pending;

static void initialize_xsave_mode(void)
{
    if(xsave_mode_initialized)
        return;

    asm volatile("xgetbv":"=d"(xsave_edx),"=a"(xsave_eax):"c"(0));

    /* CPUID.(EAX=0xD,ECX=1):EAX[1] advertises XSAVEC. */
    uint32_t eax = 0x0d;
    uint32_t ebx;
    uint32_t ecx = 1;
    uint32_t edx;
    asm volatile("cpuid"
                 : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    (void)ebx;
    (void)ecx;
    (void)edx;
    xsavec_supported = (eax >> 1) & 1;
    xsave_mode_initialized = 1;
    METRIC_INC(fpu_xcr0_initializations);
}

static void save_fpu_state(void)
{
    METRIC_TIME_START(start_cycles);
    if(xsavec_supported)
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
    if(read_cr0_clear_ts_checked(&saved_cr0))
    {
        METRIC_INC(fpu_enter_failures);
        fpu_depth = 0;
        METRIC_TIME(fpu_enter_cycles_total, fpu_enter_cycles_max,
                    start_cycles);
        return 1;
    }
    initialize_xsave_mode();
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
