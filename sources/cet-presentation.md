# Intel CET Deep Dive: Hardware Control-Flow Integrity in the Linux Kernel

## Presentation Metadata

- **Event**: Linux Summit North America 2026
- **Duration**: 30 minutes (20 min talk + 10 min Q&A)
- **Speaker**: [Speaker Name]
- **Slide Count**: 18 slides
- **Style**: Technical deep-dive with kernel source code examples
- **Audience**: Kernel developers, security engineers, systems programmers

---

## Slide 01 — Cover

**Title**: Intel CET Deep Dive
**Subtitle**: Hardware Control-Flow Integrity in the Linux Kernel
**Event**: Linux Summit North America 2026
**Speaker**: [Speaker Name]

---

## Slide 02 — Agenda

**Title**: What We'll Cover

- The Problem: ROP & JOP attacks
- Forward-Edge Integrity: Indirect Branch Tracking (IBT)
- The #CP Fault: Exception 21
- Backward-Edge Defense: Shadow Stacks
- Signal Handling & Context Switching
- The Kernel Interface: arch_prctl(2)
- Edge Cases & Production Deployment

---

## Slide 03 — The Problem: ROP & JOP

**Title**: Why Hardware CFI?

**Key Points**:
- NX bit stopped code injection → attackers chain existing code (gadgets)
- **ROP**: Chain small sequences ending in RET for arbitrary computation
- **JOP**: Chain gadgets via indirect JMP/CALL instructions
- Software mitigations (retpolines, kCFI) have performance costs and coverage gaps
- CET provides **silicon-level enforcement** — zero runtime overhead for the common case

**Diagram concept**: Show attacker chaining RET gadgets across functions vs. CET blocking the chain.

---

## Slide 04 — CET Architecture: Two Pillars

**Title**: Intel CET — Two Pillars

**Left column — Forward Edge (IBT)**:
- Restricts where indirect branches can land
- Every valid target must start with ENDBR instruction
- Protects against JOP attacks
- Kernel-only since Linux 5.18

**Right column — Backward Edge (Shadow Stacks)**:
- Hardware-enforced secondary return address stack
- CPU verifies RET targets against shadow copy
- Protects against ROP attacks
- Userspace support since Linux 6.6

**Bottom**: Both share a single exception vector: #CP (Trap 21)

---

## Slide 05 — IBT: Hardware Mechanism

**Title**: Indirect Branch Tracking — How It Works

**Flow diagram concept**:
1. CPU executes indirect CALL/JMP
2. CPU enters WAIT_FOR_ENDBRANCH (WFE) state
3. Next instruction MUST be ENDBR64 (opcode: `f3 0f 1e fa`)
4. If yes → WFE cleared, execution continues
5. If no → #CP fault (error code CP_ENDBR = 3)

**Key Points**:
- Compiler emits ENDBR at every possible indirect target (`-fcf-protection=branch`)
- Kernel boot: seals (poisons) unused ENDBR sites to reduce attack surface
- Cost: 4 bytes per valid landing site, zero runtime branch penalty

---

## Slide 06 — IBT: The gen_endbr() Trick

**Title**: Generating ENDBR Without Embedding It

**Code** (arch/x86/include/asm/ibt.h, lines 44-57):
```c
static __always_inline u32 gen_endbr(void)
{
    u32 endbr;

    /*
     * Generate ENDBR64 in a way that is sure
     * to not result in an ENDBR64 instruction
     * as immediate.
     */
    asm ( "mov $~0xfa1e0ff3, %[endbr]\n\t"
          "not %[endbr]\n\t"
           : [endbr] "=&r" (endbr) );

    return endbr;
}
```

**Annotations**:
- `mov` loads bitwise NOT: 0x05e1f00c (harmless constant)
- `not` flips to 0xfa1e0ff3 at runtime → the endbr64 opcode
- If we used `mov $0xfa1e0ff3`, those bytes in the instruction stream become a valid IBT landing pad for attackers
- `"=&r"` — early-clobber: output register written before inputs consumed

---

## Slide 07 — IBT: ENDBR Sealing at Boot

**Title**: Reducing the Attack Surface — ENDBR Sealing

**Key Points**:
- Compiler emits ENDBR everywhere "just in case"
- Many functions are NEVER indirect call targets (only called directly)
- At boot: `apply_seal_endbr()` in `arch/x86/kernel/alternative.c` replaces unnecessary ENDBRs with a poison NOP

**Code** (arch/x86/include/asm/ibt.h, lines 59-66):
```c
static u32 gen_endbr_poison(void)
{
    /*
     * 4 byte NOP that isn't NOP4, such that
     * it will be unique to (former) ENDBR sites.
     */
    return 0xd6401f0f; /* nopl -42(%rax) */
}
```

**Result**: Fewer valid landing sites = smaller gadget attack surface. Objtool identifies which ENDBRs can be sealed at build time.

---

## Slide 08 — The #CP Fault: Exception 21

**Title**: Control Protection Exception — Error Codes

**Code** (arch/x86/kernel/cet.c, lines 8-18):
```c
enum cp_error_code {
    CP_EC        = (1 << 15) - 1, /* mask */

    CP_RET       = 1,  /* RET mismatch    */
    CP_IRET      = 2,  /* far RET / IRET  */
    CP_ENDBR     = 3,  /* missing ENDBR   */
    CP_RSTRORSSP = 4,  /* RSTORSSP failed */
    CP_SETSSBSY  = 5,  /* SETSSBSY failed */

    CP_ENCL      = 1 << 15, /* SGX enclave */
};
```

**Table**:
| Code | Trigger | CET Pillar |
|------|---------|-----------|
| CP_RET (1) | Shadow stack mismatch on RET | SHSTK |
| CP_ENDBR (3) | Indirect branch to non-ENDBR | IBT |
| CP_ENCL (bit 15) | Fault inside SGX enclave | Both |

---

## Slide 09 — #CP Dispatch Logic

**Title**: Kernel #CP Handler — Routing Faults

**Code** (arch/x86/kernel/cet.c, lines 149-162):
```c
DEFINE_IDTENTRY_ERRORCODE(exc_control_protection)
{
    if (user_mode(regs)) {
        if (cpu_feature_enabled(X86_FEATURE_USER_SHSTK))
            do_user_cp_fault(regs, error_code);
        else
            do_unexpected_cp(regs, error_code);
    } else {
        if (cpu_feature_enabled(X86_FEATURE_IBT))
            do_kernel_cp_fault(regs, error_code);
        else
            do_unexpected_cp(regs, error_code);
    }
}
```

**Annotations**:
- User-mode #CP → shadow stack violation → delivers SIGSEGV (SEGV_CPERR)
- Kernel-mode #CP → IBT violation → BUG() or WARN (configurable via `ibt=warn`)
- FRED-aware: must clear WFE state in regs->fred_cs.wfe after handling

---

## Slide 10 — Shadow Stacks: How They Work

**Title**: Hardware Shadow Stack — The Mechanism

**Diagram concept — two parallel stacks**:

| Normal Stack (read/write) | Shadow Stack (read-only) |
|---------------------------|--------------------------|
| local vars, args          | return addr only         |
| return addr ← RET reads  | return addr ← CPU checks |
| saved RBP                 |                          |

**Key Points**:
- CALL pushes return address to BOTH stacks simultaneously
- RET pops from both and compares — mismatch = #CP (CP_RET)
- Shadow stack is NOT writable by normal MOV/PUSH instructions
- Only CALL, RET, and special CET instructions (WRSS, INCSSP) modify it
- MSR_IA32_PL3_SSP holds the current user Shadow Stack Pointer

---

## Slide 11 — Shadow Stack: Enabling

**Title**: Enabling Shadow Stacks — shstk_setup()

**Code** (arch/x86/kernel/shstk.c, lines 149-177):
```c
static int shstk_setup(void)
{
    struct thread_shstk *shstk =
        &current->thread.shstk;
    unsigned long addr, size;

    if (features_enabled(ARCH_SHSTK_SHSTK))
        return 0;  /* already enabled */

    size = adjust_shstk_size(0);
    addr = alloc_shstk(0, size, 0, false);

    fpregs_lock_and_load();
    wrmsrq(MSR_IA32_PL3_SSP, addr + size);
    wrmsrq(MSR_IA32_U_CET, CET_SHSTK_EN);
    fpregs_unlock();

    shstk->base = addr;
    shstk->size = size;
    features_set(ARCH_SHSTK_SHSTK);
    return 0;
}
```

**Annotations**:
- Size: min(RLIMIT_STACK, 4GB), page-aligned
- Allocated above 4GB (MAP_ABOVE4G) to prevent 32-bit aliasing
- SSP starts at top (stacks grow down)
- Guard page between adjacent shadow stacks (INCSSP max reach = 2040 bytes < 4096)

---

## Slide 12 — Signal Handling: The Challenge

**Title**: Signals vs. Shadow Stacks

**Problem**:
- Signal delivery diverts control flow to handler
- Handler returns via sa_restorer trampoline (RET)
- Shadow stack still expects the original caller's return address
- Without fixup → #CP fault on every signal return

**Solution — Signal Delivery Protocol**:
1. Push a **sigframe token** (old SSP | bit 63) — marked as "not a return address"
2. Push **sa_restorer** address onto shadow stack
3. Update MSR_IA32_PL3_SSP to new position
4. Handler's RET matches sa_restorer ✓
5. rt_sigreturn validates token, restores original SSP

**Security**: Attacker cannot forge tokens without WRSS or kernel access.

---

## Slide 13 — Signal Handling: Implementation

**Title**: setup_signal_shadow_stack()

**Code** (arch/x86/kernel/shstk.c, lines 384-416):
```c
int setup_signal_shadow_stack(struct ksignal *ksig)
{
    void __user *restorer =
        ksig->ka.sa.sa_restorer;
    unsigned long ssp;

    ssp = get_user_shstk_addr();

    /* Push sigframe token: old_ssp | BIT(63) */
    shstk_push_sigframe(&ssp);

    /* Push restorer so handler's RET matches */
    ssp -= SS_FRAME_SIZE;
    write_user_shstk_64(
        (u64 __user *)ssp, (u64)restorer);

    fpregs_lock_and_load();
    wrmsrq(MSR_IA32_PL3_SSP, ssp);
    fpregs_unlock();

    return 0;
}
```

**Annotations**:
- SHSTK_DATA_BIT (bit 63) ensures token can never match a RET
- sa_restorer = __restore_rt in vDSO (calls rt_sigreturn)
- restore_signal_shadow_stack() reverses this on sigreturn

---

## Slide 14 — Fork / Clone / Context Switch

**Title**: Shadow Stack Lifecycle — Fork, Threads, vfork

**Code** (arch/x86/kernel/shstk.c, lines 186-226, simplified):
```c
unsigned long shstk_alloc_thread_stack(
    struct task_struct *tsk, u64 clone_flags,
    unsigned long stack_size)
{
    if (clone_flags & CLONE_VFORK) {
        shstk->base = 0; /* share parent's */
        shstk->size = 0;
        return 0;
    }
    if (!(clone_flags & CLONE_VM))
        return 0; /* fork: COW handles it */

    /* pthread_create: new shadow stack */
    size = adjust_shstk_size(stack_size);
    addr = alloc_shstk(0, size, 0, false);
    shstk->base = addr;
    shstk->size = size;
    return addr + size;  /* new SSP */
}
```

**Table**:
| Scenario | Flags | Shadow Stack Action |
|----------|-------|-------------------|
| fork() | !CLONE_VM | COW copy (free) |
| vfork() | CLONE_VFORK | Share parent's |
| pthread_create() | CLONE_VM | Allocate new |

---

## Slide 15 — Context Switch: SSP in XSAVE

**Title**: SSP During Context Switch

**Code** (arch/x86/kernel/fpu/core.c, lines 634-658):
```c
static int update_fpu_shstk(struct task_struct *dst,
                            unsigned long ssp)
{
    struct cet_user_state *xstate;

    if (!ssp)
        return 0;

    xstate = get_xsave_addr(
        &x86_task_fpu(dst)->fpstate->regs.xsave,
        XFEATURE_CET_USER);

    xstate->user_ssp = (u64)ssp;
    return 0;
}
```

**Key Points**:
- SSP stored in XSAVE area under XFEATURE_CET_USER
- Context switch: XSAVE saves outgoing SSP, XRSTOR loads incoming SSP
- No explicit MSR read/write in the scheduler fast path
- fpu_clone() calls update_fpu_shstk() to set child's initial SSP

---

## Slide 16 — The Kernel Interface: arch_prctl(2)

**Title**: Userspace Control — arch_prctl(2) for CET

**Code** (arch/x86/include/uapi/asm/prctl.h + shstk.c):
```c
/* UAPI constants */
#define ARCH_SHSTK_ENABLE   0x5001
#define ARCH_SHSTK_DISABLE  0x5002
#define ARCH_SHSTK_LOCK     0x5003
#define ARCH_SHSTK_UNLOCK   0x5004
#define ARCH_SHSTK_STATUS   0x5005

/* Feature bits */
#define ARCH_SHSTK_SHSTK    (1ULL << 0)
#define ARCH_SHSTK_WRSS     (1ULL << 1)
```

**Usage Pattern**:
```c
/* Enable shadow stack */
arch_prctl(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK);

/* Lock — prevents attacker from disabling */
arch_prctl(ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK);
```

**Key Points**:
- LOCK prevents disable even by the process itself
- UNLOCK only via ptrace (for CRIU/checkpoint-restore)
- glibc enables automatically for CET-compiled binaries (GNU property notes)

---

## Slide 17 — Edge Cases & Production

**Title**: Edge Cases & Deployment

**setjmp / longjmp**:
- longjmp skips intermediate frames → shadow stack has stale entries
- Solution: glibc uses INCSSP to advance past stale frames
- Deep longjmp may require WRSS (separate opt-in via arch_prctl)

**JIT Engines (V8, LuaJIT, eBPF)**:
- Must emit ENDBR at all generated indirect targets
- map_shadow_stack syscall for custom coroutine stacks
- eBPF JIT: tail calls must land on ENDBR

**GLIBC_TUNABLES — Production Override**:
```bash
GLIBC_TUNABLES=glibc.cpu.hwcaps=-SHSTK ./app
```
- Disables shadow stacks at dynamic linker level
- Useful for legacy apps, debugging, incompatible JITs
- Per-process, no kernel restart needed

---

## Slide 18 — Timeline & Key Takeaways

**Title**: Summary & Timeline

**Timeline**:
| Version | Milestone |
|---------|-----------|
| Linux 5.18 (May 2022) | Kernel IBT merged |
| Linux 6.4 (Jun 2023) | FineIBT (type-based CFI) |
| Linux 6.6 (Oct 2023) | Userspace Shadow Stacks |
| Linux 6.6+ | map_shadow_stack syscall |

**Key Takeaways**:
- CET = hardware CFI with zero performance tax on the fast path
- IBT: forward-edge, ENDBR + sealing + #CP
- Shadow Stacks: backward-edge, read-only return stack + signal tokens
- Production-ready: glibc integration, arch_prctl locking, GLIBC_TUNABLES escape hatch
- All implementation in ~5 files under arch/x86/

**Closing**: Questions?

---

## Key Source Files Reference

| File | Role |
|------|------|
| arch/x86/kernel/cet.c | #CP exception handler |
| arch/x86/kernel/shstk.c | Shadow stack lifecycle |
| arch/x86/include/asm/ibt.h | IBT macros & gen_endbr() |
| arch/x86/kernel/fpu/core.c | SSP in XSAVE context |
| arch/x86/include/uapi/asm/prctl.h | Userspace API |
| arch/x86/kernel/alternative.c | ENDBR sealing |
