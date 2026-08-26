# kstuff-lite — `1.11-opt`

`1.11-opt` is an optimization and firmware-porting branch built on top of the
existing kstuff-lite crypto, FSELF, NPDRM, and loader work. Relative to
`origin/main`, it contains 18 commits focused on reducing UELF/KELF transition
cost, making FPU/CR0 handling safer and faster, improving diagnostics, and
adding firmware 2.50 support.

## Highlights

- Firmware 2.50 support, including kernel offsets, the older PCB layout, the
  2.50 kernel-data anchor adjustment, and retail ShellCore patches.
- Cached translations for fixed per-CPU kernel objects used on every UELF
  entry, including mappings that cross a physical segment boundary.
- Narrow checked trap-frame and stack reads instead of copying unused frame
  prefixes.
- A single-transition debug-register restore and skipped hardware snapshots
  when the current thread does not own active debug registers.
- A validated, normally fault-free CR0 save/TS-clear chain for 2.50, 4.03,
  7.61, and 9.40.
- Fast CR0 entry through a one-shot KELF continuation and deferred CR0 restore
  at the final KELF exit.
- Runtime selection between `XSAVEC` and `XSAVE`, with one-time CPUID/XCR0
  discovery and strict save-area validation.
- Expanded opt-in performance and failure metrics through `KSTUFF_OBS=1`.
- Reuse of the loader's existing kernel pipe by prosper0gdb.

## UELF trap and kernel-memory paths

### Narrow checked frame reads

Trap handlers now read only the portion of a saved stack frame that they use.
`fpkg`, `kekcall`, and utility trap handling use checked tail-copy helpers;
mailbox and syscall paths use checked scalar reads and writes. Where the return
address is already known, FSELF handling updates `RSP` and `RIP` directly
instead of reading the same value from kernel memory again.

This reduces `virt2phys` calls and copied bytes without weakening error
handling. A failed read or write returns `EFAULT` or leaves the request on its
normal fallback path instead of consuming partially read state.

### Fixed mapping caches

The following stable per-CPU objects have cached virtual-to-physical mappings:

- the extended trap frame;
- the `justreturn` frame;
- the current-thread pointer in `pcpu`;
- `TSS.RSP0`;
- the `wrmsr` argument area;
- the CR0 enter and exit continuation slots.

The cache can represent two physical segments, so an object crossing a page or
mapping boundary does not need to fall back on every access. Initialization is
checked, publication is atomic, and an uncached checked copy remains available
if a mapping cannot be cached.

The UELF page-table setup also spells out the user, writable, present, and
large-page flags explicitly. Direct-map entries are not made global, avoiding
unsafe stale TLB translations when switching between the kernel and UELF CR3.

## Crypto dispatch

Each crypto message is read once as a checked snapshot of the first 21 qwords
(168 bytes), followed by a separate checked 8-byte read of the linked-list
pointer at `msg + 320`. The implementation does **not** perform a contiguous
328-byte read.

During classification, the fake key is retrieved once and passed to the XTS or
HMAC handler. This removes the former `has_fake_key()` lookup followed by a
second `get_fake_key()` lookup. XTS and HMAC cache selection also performs one
scan that records both a matching entry and the first free entry.

Unhandled or non-fake messages retain the normal firmware path, and linked
message chains are still traversed correctly. Snapshot read failures are
counted and fail safely.

## Debug-register transitions

Debug-register restore now enters the verified tail of the kernel
`cpu_switch` implementation and restores DR0, DR1, DR2, DR3, DR6, and DR7 in a
single gadget transition. The 2.50 and 3.00+ helper layouts use their own
validated entry deltas.

Before installing a watchpoint, the code checks `PCB_DBREGS`. If the flag is
clear, the thread does not own live hardware debug-register state, so a stale
hardware snapshot is skipped and the saved state is initialized as disabled.
PCB flags are accessed as a 32-bit field, and rollback restores both the old
registers and the original ownership flag if installation fails.

KELF 8-byte writes also use a scalar `mov [rdi], rax` store helper instead of
configuring `rep movsb` for every single-qword update.

## FPU and CR0 handling

### Layered CR0 entry

UELF crypto uses SIMD instructions and must preserve kernel FPU state while
temporarily clearing `CR0.TS`. The branch implements three paths:

1. On 2.50, 4.03, 7.61, and 9.40, the primary path runs a firmware-specific
   KELF chain that captures CR0, clears TS, commits the new value, and records
   all three states without deliberately causing a second XSAVE/FXSAVE fault.
2. If the chain has been disabled, a firmware-specific `fpusave_capture`
   fallback deliberately faults on a non-canonical XSAVE/FXSAVE destination.
   It accepts the result only when the trap is `#GP`, RIP is exactly the
   expected XSAVE or FXSAVE instruction, and the captured CR0 value is sane.
3. Firmware without verified offsets uses the original checked CR0 read and
   write gadgets. If TS is already clear, the write transition is skipped.

The primary chain poisons and transfers one compact `0x60`-byte result block,
then validates the saved, cleared, and committed values. A mismatch restores
TS when possible, disables the fast chain, and reports failure instead of
trusting partial state.

### Fast entry and deferred restore

For the primary path, UELF arms a one-shot KELF continuation and performs one
`yield()`; KELF resets the hook before running the CR0 chain. This bypasses the
generic full-register gadget return path. The fixed continuation address and
its physical mapping are cached after the first use.

After `XRSTOR`, CR0 restoration is postponed until `uelf_fpu_finish()`, just
before the terminal UELF `HLT`. KELF then restores CR0 and continues through
the normal final exit. Nested FPU users share the outer save/restore pair, so
they do not add extra CR0 or XSAVE transitions.

### XSAVE mode selection

CPUID and XCR0 discovery is performed once per UELF instance. Before using an
architectural save instruction, the code verifies:

- CPUID exposes leaf `0xD`;
- the CPU and OS expose XSAVE/OSXSAVE;
- x87 and SSE are enabled in XCR0;
- XCR0 contains only state components reported by CPUID;
- `CPUID.(D,0):EBX` is within the architectural minimum, the reported maximum,
  and the 4096-byte aligned local buffer.

`XSAVEC` is selected when `CPUID.(D,1):EAX[1]` advertises it; otherwise the code
uses `XSAVE`. Restore always uses `XRSTOR`. `XSAVEOPT` is deliberately not used
because the scratch buffer is not guaranteed to contain the same owner's
previous state. An unusable configuration disables FPU entry cleanly instead
of overflowing the buffer or executing an unsupported instruction.

## prosper0gdb loader handoff

The loader passes prosper0gdb a versioned bootstrap structure containing its
existing read/write pipe descriptors and kernel pipe address. prosper0gdb
reuses that primitive instead of allocating and resolving another pipe. The
older `victim_pktopts` ABI remains recognized for callers that do not provide
the bootstrap magic.

On firmware 2.50, the loader-provided SDK data anchor differs from the anchor
used to generate the prosper0gdb offset table by `0x1010000`; the handoff now
applies that adjustment only on 2.50.

## Observability

Build with metrics and the debug reader enabled:

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
KSTUFF_OBS=1 ./ci-ps5-kstuff-ldr.sh
```

A normal build keeps the extra counters out of hot paths:

```sh
./ci-ps5-kstuff-ldr.sh
```

The added metrics cover:

- UELF entries, checked frame failures, and total/max entry cycles;
- gadget calls, failures, result-readback reductions, and cycles;
- scalar and bulk kernel copies;
- crypto snapshot reads, failures, and cycles;
- mapping-cache hits, misses, and fallbacks;
- debug-register reads, writes, single-transition chains, and skipped
  snapshots;
- CR0 fast-entry/deferred-restore arms, fallbacks, failures, hook-cache use,
  and arm cost;
- FPU enter/exit, XSAVE/XSAVEC/XRSTOR counts, failures, and cycle cost.

`ps5-kstuff/debug-reader.c` prints these counters from the shared observation
area. Metrics are intended for comparison runs; they add measurement overhead
and should not be used as release-performance numbers.

## Firmware porting notes

All code locations which must be audited for a new firmware carry the literal
marker `TODO(FW_PORT)`. List them before starting a port:

```sh
rg 'TODO\(FW_PORT\)' prosper0gdb ps5-kstuff ps5-kstuff-ldr
```

The required audit is broader than adding one kernel offset file:

- create and register `prosper0gdb/offsets/<fw>.h`, resolving every item in
  `offset_list.txt` against the exact executable kernel image;
- create, include, and register the matching SceShellCore retail/testkit/devkit
  patch table, checking original bytes at every patch site;
- verify the elfldr/kdata anchor, PCPU/GDT/TSS/PCB layouts, `vmspace->vm_pmap`,
  syscall frame, FSELF mailbox frame, FPKG message-head register, and mini
  syscore header size;
- add the optional CR0/FPU fast-path gadgets only after their complete
  contracts have been verified. Unsupported optional gadgets must remain the
  nonzero sentinel `1`, which selects the checked legacy path.

CR0 fast-path offsets are firmware-specific and must not be copied from a
nearby version. `ps5-kstuff/main.c` contains the complete search and validation
procedure for `cr0_capture`, `cr0_load`, `cr0_clear_store`, and
`cr0_write_ret`, including byte-pattern seeds and the IDA-to-runtime address
conversion.

For each currently unlisted firmware, search executable/XO kernel code in IDA
for these seeds, then validate the entire basic block and epilogue:

- `fpusave_capture`: `0f 20 c1 0f 06 83 3d ?? ?? ?? ?? 00`, entering at
  `mov rcx,cr0; clts`; independently record the following XSAVE and FXSAVE RIPs;
- `cr0_capture`: `0f 20 c0 48 89 47 58`, requiring
  `[rdi+0x58] = CR0`;
- `cr0_load`: `48 8b 47 58`, requiring `rax = [rdi+0x58]`;
- `cr0_clear_store`: search from `and rax,-9` (`48 83 e0 f7`) to the store
  through RSI, requiring `rax &= ~CR0_TS` and `[rsi] = rax`;
- `cr0_write_ret`: `0f 22 c0`, requiring `CR0 = rax` followed by either `ret`
  or `pop rbp; ret`;
- `store_rax_rdi`: `48 89 07 c3` or `48 89 07 5d c3`, requiring only
  `[rdi] = rax` and the supported epilogue;
- the `cpu_switch` debug-register tail: find the sequence restoring
  DR0/DR1/DR2/DR3/DR6/DR7 from PCB offsets and select the entry which reaches
  the final `xor eax,eax`; the zero return is its completion marker.

Convert an IDA address using the same anchor as its prosper0gdb table:

```text
runtime = kdata_base + (gadget_ea - ida_kdata_anchor_ea)
```

The normal CR0-enter path does not execute the remainder of the large
`cr0_capture` helper. KELF single-steps the already verified `mov_rax_cr0`
offset, catches the resulting one-shot `#DB`, and places the captured RAX
directly in the helper-compatible `saved` slot. The existing clear/write chain
then continues without another UELF round trip. The full `cr0_capture` helper
remains the fallback when the fast-entry hook cannot be armed.

For a new firmware, add all four verified offsets together. If any helper's
register, stack, or epilogue contract is uncertain, leave the fast path
unavailable and use the checked legacy implementation. An observation build
should show increasing `cr0_chain_enter`, `cr0_fast_enter`, and
`cr0_defer_arm`, with zero `cr0_chain_fail` and no unexpected fallbacks.
Compare `cr0_enter_avg` between otherwise identical observation runs; the
one-shot trap and its KELF continuation are part of that number, while
`enter_arm_avg` measures only the hook write.

## Existing functionality retained from the parent branch

The branch retains the earlier kstuff-lite work: cached XTS/HMAC state,
batched and direct-DMEM PFS crypto paths, FSELF header/context caches, lazy
`authinfo`, overlap-safe SELF block copies, NPDRM/RIF caching, Zen 2-tuned
`isa-l_crypto`, checked kernel copy helpers, improved error handling, optimized
startup allocation, and the option to disable automatic mounting.
