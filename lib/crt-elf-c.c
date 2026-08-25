#include <sys/types.h>
#include "r0gdb-bootstrap.h"

struct specter_args
{
    void* dlsym;
    int* pipe;
    int* rwpair;
    uint64_t kpipe_addr;
    uint64_t kdata_base;
    int* retval;
};

uint64_t _start(void* dlsym, int master, int victim, uint64_t pktopts, uint64_t kdata_base);

void elf_main(struct specter_args* args)
{
    struct r0gdb_bootstrap bootstrap = {
        .magic = R0GDB_BOOTSTRAP_MAGIC,
        .rwpipe = {args->pipe[0], args->pipe[1]},
        .kpipe_addr = args->kpipe_addr,
    };
    *args->retval = _start(args->dlsym,
                           args->rwpair[0],
                           args->rwpair[1],
                           (uint64_t)&bootstrap,
                           args->kdata_base);
}
