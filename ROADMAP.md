# XNU-Compatible AArch64 Darwin Kernel in Rust — Roadmap

> Goal: boot a Rust kernel on QEMU AArch64, reach Darwin userspace, load dyld shared cache, and eventually start host `zsh` as the first interactive shell.

## Design goals
- **Nightly Rust only** for low-level kernel work.
- **Safety-first**: aggressive Clippy and Rust lints; all `unsafe` blocks documented with invariants.
- **Modular architecture**: keep arch-specific code isolated under `src/arch/<arch>/` for future x86_64 / other ARM variants.
- **QEMU-first bring-up**: target `qemu-system-aarch64 -M virt`.
- **Incremental compatibility**: implement just enough XNU/Mach/Darwin behavior to get dyld and then `zsh` running.

## Required crates
- `log` — kernel logging
- `spin` — early boot synchronization / minimal locks
- `goblin` — Mach-O / fat binary parsing
- `arm-gic` — interrupt controller support
- `aarch64-cpu` — CPU/system registers and EL setup
- `aarch64-paging` — page table management

## Current workspace scaffold
- Root `Cargo.toml` defines the workspace, shared dependencies, and lint policy.
- `kernel/Cargo.toml` is the `no_std` kernel crate.
- `kernel/src/` contains the modular kernel skeleton.

## Proposed kernel layout
```text
kernel/
  Cargo.toml
  src/
    lib.rs
    arch/
      mod.rs
      aarch64/
        mod.rs
        boot.rs
        cpu.rs
        exception.rs
        gic.rs
        mmu.rs
        context.rs
        syscall.rs
        smp.rs
    mm/
      mod.rs
      frame.rs
      vma.rs
      pager.rs
      mapping.rs
    alloc/
      mod.rs
      slab.rs
      buddy.rs
    sched/
      mod.rs
      task.rs
      thread.rs
      runqueue.rs
      context_switch.rs
    ipc/
      mod.rs
      mach_port.rs
      mach_msg.rs
      rights.rs
    mach/
      mod.rs
      bootstrap.rs
      host.rs
      task.rs
      thread.rs
      traps.rs
    exec/
      mod.rs
      macho.rs
      dyld.rs
      loader.rs
    fs/
      mod.rs
      vnode.rs
      devfs.rs
      initrd.rs
    util/
      mod.rs
      bitfield.rs
      sync.rs
      error.rs
```

## Rust feature gates / lint policy

### Nightly features (likely needed)
- `global_asm`
- `naked_functions`
- `asm_experimental_arch`
- `alloc_error_handler`
- `link_section`
- `repr_align_enum` if required by ABI/layout work

### Lints to enable early
```rust
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]
```

### Safety conventions
- Every `unsafe` block must state the invariants it depends on.
- Avoid `spin` locks in hot paths once scheduler-aware primitives exist.
- Prefer small, testable modules with explicit ownership of mappings, frames, and ports.

---

# Multi-phase implementation plan

## Phase 0 — Repo scaffolding and build target
**Goal:** create a clean foundation for all later work.

### Tasks
- Initialize Cargo workspace and kernel crate(s).
- Add `rust-toolchain.toml` pinned to nightly.
- Add target JSON for AArch64 QEMU `virt` machine.
- Add linker script and boot image packaging.
- Create basic module skeleton above.
- Add CI/build scripts for `cargo check`, `clippy`, and image generation.

### Exit criteria
- Kernel compiles for AArch64 target.
- QEMU boots the image to the first instruction in Rust/assembly entry code.

---

## Phase 1 — Boot, UART, logging, panic, and exceptions
**Goal:** see controlled output and fail safely.

### Tasks
- Set up EL transition / boot handoff.
- Initialize UART console and `log` backend.
- Install exception vector table.
- Implement panic handler and early diagnostic output.
- Decode and print synchronous exceptions, IRQs, FIQs, and SError.
- Wire `arm-gic` for interrupts.

### Module checklist
- `arch/aarch64/boot.rs`
- `arch/aarch64/exception.rs`
- `arch/aarch64/gic.rs`
- `util/error.rs`

### Exit criteria
- Kernel prints boot logs.
- Exceptions are classified and visible.
- Timer/IRQ interrupts can be acknowledged.

---

## Phase 2 — Memory management and paging
**Goal:** establish stable virtual memory.

### Tasks
- Detect RAM and reserved regions.
- Implement frame allocator.
- Bring up `aarch64-paging` for kernel page tables.
- Map kernel text/data/rodata and device MMIO regions.
- Create higher-half kernel mapping.
- Add early bump allocator, then replace with a real heap allocator.
- Add per-CPU kernel stacks.

### Module checklist
- `mm/frame.rs`
- `mm/mapping.rs`
- `mm/pager.rs`
- `alloc/buddy.rs`
- `alloc/slab.rs`
- `arch/aarch64/mmu.rs`

### Exit criteria
- Can map/unmap pages safely.
- Kernel heap allocations work without boot-time hacks.
- Faults on invalid access are reported, not fatal-by-default.

---

## Phase 3 — CPU context, threads, and scheduling
**Goal:** support kernel/user context switching.

### Tasks
- Define `Task`, `Thread`, `AddressSpace`, and per-thread register state.
- Implement save/restore of AArch64 CPU context.
- Add scheduler run queue.
- Support timer preemption.
- Add per-CPU data and boot SMP scaffolding (single-core first).
- Prepare user-mode entry/return path.

### Module checklist
- `sched/task.rs`
- `sched/thread.rs`
- `sched/runqueue.rs`
- `sched/context_switch.rs`
- `arch/aarch64/context.rs`
- `arch/aarch64/smp.rs`

### Exit criteria
- Kernel threads can yield and resume.
- User/kernel transition path exists.
- Scheduler is stable enough for simple user tasks.

---

## Phase 4 — Mach IPC nucleus
**Goal:** implement the core Mach message/port model.

### Tasks
- Implement Mach port objects and rights.
- Support send/receive queues and basic message descriptors.
- Implement `mach_msg` kernel path.
- Add special ports (`host`, `task`, `thread`, bootstrap placeholders).
- Add port allocation/insertion/deallocation.
- Stub out out-of-line memory descriptors initially, then implement them.

### Minimum API target
- `mach_task_self()`
- `mach_port_allocate()`
- `mach_port_insert_right()`
- `mach_msg()`
- `mach_port_deallocate()`

### Module checklist
- `ipc/mach_port.rs`
- `ipc/mach_msg.rs`
- `ipc/rights.rs`
- `mach/bootstrap.rs`
- `mach/host.rs`
- `mach/task.rs`
- `mach/thread.rs`

### Exit criteria
- A minimal user process can exchange Mach messages with the kernel.
- Special ports resolve correctly.

---

## Phase 5 — Darwin syscall surface
**Goal:** provide enough syscalls for dyld startup and basic libc use.

### Tasks
- Implement syscall entry/dispatch on AArch64.
- Build a syscall table with per-call validation.
- Add process/thread queries and basic task info.
- Add memory-management calls (`mmap`, `mprotect`, `munmap`, `vm_*` variants as needed).
- Add file/descriptor basics (`open`, `close`, `read`, `write`, `fcntl`, `stat`).
- Add time/signal stubs sufficient for startup.
- Add compatibility shims for `errno`-style failure behavior.

### Priority syscalls
1. `mmap`, `munmap`, `mprotect`
2. `getpid`, `exit`, `thread_selfid`
3. `open`, `close`, `read`, `write`
4. `task_info`, `thread_info`, `host_info`
5. `mach_vm_*` / `vm_*` variants required by dyld

### Exit criteria
- dyld can query memory and process state without crashing.
- Userland can open and read basic files.

---

## Phase 6 — Mach-O loader and dyld shared cache
**Goal:** load Darwin binaries and let dyld map the shared cache.

### Tasks
- Implement Mach-O parsing with `goblin`.
- Support fat binaries and slice selection.
- Parse load commands and segment mappings.
- Map `__TEXT`, `__DATA`, `__LINKEDIT`, and related segments.
- Support page alignment, protections, and slide calculations.
- Implement rebasing/binding/fixup handling as needed.
- Add shared cache detection/mapping behavior.
- Make VM semantics match dyld expectations more closely.

### Module checklist
- `exec/macho.rs`
- `exec/dyld.rs`
- `exec/loader.rs`
- `mm/vma.rs`

### Exit criteria
- dyld loads and maps its shared cache.
- A Darwin user binary can start resolving symbols.

---

## Phase 7 — Userspace bootstrap and shell bring-up
**Goal:** reach an interactive shell in QEMU.

### Tasks
- Launch first userspace bootstrap process.
- Provide root filesystem / initramfs / image contents.
- Set up environment variables (`PATH`, `HOME`, `TERM`, etc.).
- Provide console and TTY-like behavior.
- Load and run `/usr/lib/dyld`-driven binaries.
- Start host `zsh` as the entrypoint if compatible.

### Exit criteria
- QEMU boots to userspace.
- dyld resolves and loads the shell stack.
- `zsh` reaches a prompt.

---

## Phase 8 — XNU compatibility hardening
**Goal:** expand coverage and reduce stubs.

### Tasks
- Improve Mach IPC correctness and edge cases.
- Expand signal handling and exception delivery.
- Fill in missing `task_*`, `thread_*`, and `host_*` behaviors.
- Improve VM accounting and copy-on-write behavior.
- Add more Darwin file system and process semantics.
- Add tracing and invariant checks for unsafe paths.
- Build regression tests around dyld and shell startup.

### Exit criteria
- System boots reproducibly.
- Most early dyld/userland stubs are replaced with real implementations.
- Compatibility gaps are documented and shrinking.

---

# Suggested implementation order by dependency
1. Boot + UART + logging
2. Exceptions + GIC + timer IRQs
3. Paging + heap allocator
4. Context switching + threads
5. Mach ports + `mach_msg`
6. Syscall dispatcher + memory syscalls
7. Mach-O loader + dyld cache mapping
8. Root image + userspace init
9. `zsh` bring-up
10. Compatibility hardening

# Done definition for the project
The project is “working” when:
- QEMU boots the kernel successfully.
- A Darwin userspace process starts.
- dyld loads its shared cache.
- `zsh` runs as the entrypoint in userspace.

# Notes
- Keep architecture-independent logic in shared modules; only hardware-specific code should live in `arch/aarch64/`.
- Prefer small compatibility shims early, but replace them with correct semantics as soon as dyld or libc demands it.
- Treat every new syscall or Mach primitive as a contract: validate inputs, document invariants, and add regression coverage.
