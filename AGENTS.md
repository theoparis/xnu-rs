# AGENTS.md

## Project workflow

This repository is a Rust workspace for an XNU-compatible AArch64 Darwin kernel.

### Standard commands
- `cargo xtask check`
- `cargo xtask clippy`
- `cargo xtask fmt`
- `cargo xtask build-image`
- `cargo xtask run`

### Build flow
1. Edit kernel, loader, or xtask code.
2. Run `cargo xtask check`.
3. Run `cargo xtask clippy`.
4. Run `cargo xtask build-image` to build the UEFI loader and generate a GPT/ESP disk image.
5. Run `cargo xtask run` to launch QEMU with the current kernel.

### QEMU notes
- Target machine: `qemu-system-aarch64 -M virt,virtualization=on`
- Console: `-nographic -serial mon:stdio`
- Boot path is UEFI via OVMF/EDK2 firmware and an ESP image.
- `xtask build-image` stages `target/qemu/bundle/` and creates a GPT disk image at `target/qemu/images/esp.img`.
- The UEFI loader crate currently reads `KERNEL` from the ESP, loads its Mach-O segments, builds XNU-style boot args/device tree data, exits boot services, switches to a loader-owned stack, and jumps to the Mach-O entrypoint.
- The AArch64 kernel is linked by `kernel/linker/aarch64.ld` at `0x40200000`, inside QEMU virt RAM, so the loader can load it at linked physical addresses without relocation.
- `xtask build-image` converts the built kernel ELF into a minimal Mach-O image for boot-time loading.
- The Mach-O-specific loader logic lives in the `loader/` crate and can be expanded as Darwin userspace support grows.
- The ESP contains `EFI/BOOT/BOOTAA64.EFI` plus `KERNEL` at the root for early boot/testing; `KERNEL` is the generated Mach-O payload.

### Debugging workflow
Assume the host has `radare2` and `r2ghidra` installed.

Useful commands:
- `radare2 target/aarch64-unknown-none/debug/kernel`
- `r2 -A target/aarch64-unknown-none/debug/kernel`
- In `r2`, use `aaa` then `pdf @ sym.<name>` to inspect code.
- Use `r2ghidra` for decompilation when control-flow or syscall logic gets large.

Suggested debugging loop:
1. Build the kernel and loader with debug info.
2. Inspect symbols and disassembly in `radare2`.
3. Use `r2ghidra` to review complex routines.
4. Re-run `xtask` checks and QEMU.

### Safety policy
- Keep `unsafe` small and documented.
- Prefer architecture-specific code under `kernel/src/arch/aarch64/`.
- Preserve workspace lint policy in root `Cargo.toml`.
