#include "utils.h"
#include "shared_area.h"

__attribute__((aligned(64))) static char xsave_area[4096]; //is this enough?
static uint32_t xsave_eax, xsave_edx;
static uint64_t saved_cr0;
static uint32_t fpu_depth;
static uint32_t fpu_state_saved;

int uelf_fpu_enter(void)
{
    if(fpu_depth++)
    {
        METRIC_INC(fpu_nested_enters);
        return 0;
    }
    METRIC_INC(fpu_enters);
    fpu_state_saved = 0;
    if(read_cr0_clear_ts_checked(&saved_cr0))
    {
        METRIC_INC(fpu_enter_failures);
        fpu_depth = 0;
        return 1;
    }
    asm volatile("xgetbv":"=d"(xsave_edx),"=a"(xsave_eax):"c"(0));
    asm volatile("xsave %0":"=m"(xsave_area):"a"(xsave_eax),"d"(xsave_edx));
    asm volatile("finit");
    uint32_t mxcsr = 0x1f80;
    asm volatile("ldmxcsr %0"::"m"(mxcsr));
    fpu_state_saved = 1;
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
    asm volatile("xrstor %0"::"m"(xsave_area),"a"(xsave_eax),"d"(xsave_edx));
    if((saved_cr0 & 8) && write_cr0_checked(saved_cr0))
        METRIC_INC(fpu_exit_failures);
    fpu_state_saved = 0;
}
