#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::undocumented_unsafe_blocks,
    clippy::option_if_let_else
)]

use crate::arch::uart;

use super::SyscallContext;

// ── Darwin BSD syscall numbers ─────────────────────────────────────────────
const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_RECVFROM: u64 = 29;
const SYS_GETEGID: u64 = 43;
const SYS_SIGACTION: u64 = 46;
const SYS_GETGID: u64 = 47;
const SYS_SIGPROCMASK: u64 = 48;
const SYS_SIGALTSTACK: u64 = 53;
const SYS_IOCTL: u64 = 54;
const SYS_FCNTL: u64 = 92;
const SYS_SOCKET: u64 = 97;
const SYS_CONNECT: u64 = 98;
const SYS_GETTIMEOFDAY: u64 = 116;
const SYS_GETRUSAGE: u64 = 117;
const SYS_GETSOCKOPT: u64 = 118;
const SYS_WRITEV: u64 = 121;
const SYS_SENDTO: u64 = 133;
const SYS_PREAD: u64 = 153;
const SYS_PWRITE: u64 = 154;
const SYS_CSOPS: u64 = 169;
const SYS_CSOPS_AUDITTOKEN: u64 = 170;
const SYS_SIGRETURN: u64 = 184;
const SYS_GETRLIMIT: u64 = 194;
const SYS_SETRLIMIT: u64 = 195;
const SYS_MMAP: u64 = 197;
const SYS_LSEEK: u64 = 199;
const SYS_SYSCTL: u64 = 202;
const SYS_GETUID: u64 = 24;
const SYS_GETEUID: u64 = 25;
const SYS_GETPID: u64 = 20;
const SYS_MUNMAP: u64 = 73;
const SYS_MPROTECT: u64 = 74;
const SYS_SHARED_REGION_CHECK_NP: u64 = 294;
const SYS_PROC_INFO: u64 = 336;
const SYS_STAT64: u64 = 338;
const SYS_FSTAT64: u64 = 339;
const SYS_LSTAT64: u64 = 340;
const SYS_GETDIRENTRIES64: u64 = 344;
const SYS_AUDIT: u64 = 350;
const SYS_GETAUDIT_ADDR: u64 = 357;
const SYS_BSDTHREAD_REGISTER: u64 = 366;
const SYS_WORKQ_OPEN: u64 = 456;
const SYS_GETENTROPY: u64 = 520;
const SYS_ISSETUGID: u64 = 327;
const SYS_PTHREAD_SIGMASK: u64 = 329;
const SYS_DISABLE_THREADSIGNAL: u64 = 332;
const SYS_THREAD_SELFID: u64 = 372;
const SYS_ABORT_WITH_PAYLOAD: u64 = 521;
const SYS_SETITIMER: u64 = 38;
const SYS_KQUEUE_WORKLOOP_CTL: u64 = 483;
const SYS_WORK_INTERVAL_CTL: u64 = 500;
const SYS_DUP: u64 = 41;
const SYS_DUP2: u64 = 90;
const SYS_PIPE: u64 = 42;
const SYS_CHDIR: u64 = 12;
const SYS_FCHDIR: u64 = 13;

// ── IOCTL requests ────────────────────────────────────────────────────────
const TIOCGWINSZ: u64 = 0x4008_7468;

// ── mmap flags ────────────────────────────────────────────────────────────
const MAP_ANON: u64 = 0x1000;
const MAP_FIXED: u64 = 0x0010;

// ── sysctl MIBs ──────────────────────────────────────────────────────────
const CTL_KERN: u32 = 1;
const CTL_HW: u32 = 6;
const KERN_OSTYPE: u32 = 1;
const KERN_OSRELEASE: u32 = 2;
const KERN_VERSION: u32 = 4;
const KERN_MAXFILES: u32 = 7;
const KERN_ARGMAX: u32 = 8;
const KERN_OSREV: u32 = 3;
const KERN_MAXPROC: u32 = 6;
const HW_NCPU: u32 = 3;
const HW_BYTEORDER: u32 = 9;
const HW_PAGESIZE: u32 = 7;
const HW_PHYSMEM: u32 = 5;
const HW_USERMEM: u32 = 6;
const HW_MEMSIZE: u32 = 24;
const HW_CPU_FREQ: u32 = 15;
const HW_CACHELINESIZE: u32 = 13;

// Sentinel FDs for devfs special files (above the open-file table range).
const DEV_NULL_FD: usize = 100;
const DEV_CONSOLE_FD: usize = 101;
const DEV_URANDOM_FD: usize = 102;
const DEV_ZERO_FD: usize = 103;

const fn is_dev_fd(fd: usize) -> bool {
    matches!(
        fd,
        DEV_NULL_FD | DEV_CONSOLE_FD | DEV_URANDOM_FD | DEV_ZERO_FD
    )
}

#[derive(Clone)]
struct OpenFile {
    #[allow(dead_code)]
    path: liballoc::string::String,
    data_offset: u64,
    data_size: u64,
    seek_offset: u64,
}

static OPEN_FILES: crate::util::sync::OnceLock<
    crate::util::sync::Mutex<liballoc::vec::Vec<Option<OpenFile>>>,
> = crate::util::sync::OnceLock::new();

fn open_files() -> &'static crate::util::sync::Mutex<liballoc::vec::Vec<Option<OpenFile>>> {
    OPEN_FILES.get_or_init(|| crate::util::sync::Mutex::new(liballoc::vec![None; 256]))
}

fn get_user_string(ptr: *const u8) -> Option<liballoc::string::String> {
    if ptr.is_null() {
        return None;
    }
    let mut s = liballoc::string::String::new();
    let mut offset = 0;
    loop {
        let b = unsafe { ptr.add(offset).read() };
        if b == 0 {
            break;
        }
        s.push(b as char);
        offset += 1;
        if offset > 1024 {
            return None;
        }
    }
    Some(s)
}

fn read_from_fd(fd: usize, buf: &mut [u8], offset: u64) -> Result<usize, u64> {
    let mut fds = open_files().lock();
    if fd >= fds.len() {
        return Err(9); // EBADF
    }
    let Some(file) = &mut fds[fd] else {
        return Err(9); // EBADF
    };
    if offset >= file.data_size {
        return Ok(0);
    }
    let read_len = (buf.len() as u64).min(file.data_size - offset) as usize;
    let disk_offset = file.data_offset + offset;
    if !crate::fs::xnrsfs::read_bytes(disk_offset, &mut buf[..read_len]) {
        return Err(5); // EIO
    }
    Ok(read_len)
}

#[allow(clippy::too_many_lines)]
pub(super) fn dispatch(ctx: &mut SyscallContext, nr: u64) {
    match nr {
        SYS_EXIT => {
            uart::write_str("xnu-rs: user exit(0x");
            uart::write_hex_u64(ctx.arg(0));
            uart::write_str(")\n");
            loop {
                core::hint::spin_loop();
            }
        }

        SYS_WRITE | SYS_PWRITE => {
            let fd = ctx.arg(0);
            let buf_ptr = ctx.arg(1) as *const u8;
            let raw_len = ctx.arg(2);
            if (fd == 1 || fd == 2 || fd == DEV_CONSOLE_FD as u64)
                && !buf_ptr.is_null()
                && raw_len <= 65536
            {
                let bytes = unsafe { core::slice::from_raw_parts(buf_ptr, raw_len as usize) };
                for &b in bytes {
                    uart::write_byte(b);
                }
                ctx.set_return(raw_len);
            } else {
                ctx.set_error(9); // EBADF
            }
        }

        SYS_WRITEV => sys_writev(ctx),
        SYS_READ => sys_read(ctx),
        SYS_PREAD => sys_pread(ctx),
        SYS_OPEN => sys_open(ctx),
        SYS_CLOSE => sys_close(ctx),
        SYS_LSEEK => sys_lseek(ctx),

        SYS_FORK
        | SYS_GETUID
        | SYS_GETEUID
        | SYS_GETGID
        | SYS_GETEGID
        | SYS_SIGACTION
        | SYS_SIGPROCMASK
        | SYS_SIGRETURN
        | SYS_SIGALTSTACK
        | SYS_MUNMAP
        | SYS_MPROTECT
        | SYS_SETRLIMIT
        | SYS_ISSETUGID
        | SYS_CSOPS
        | SYS_CSOPS_AUDITTOKEN
        | SYS_PROC_INFO
        | SYS_BSDTHREAD_REGISTER
        | SYS_WORKQ_OPEN
        | SYS_DISABLE_THREADSIGNAL
        | SYS_PTHREAD_SIGMASK
        | SYS_GETDIRENTRIES64
        | SYS_AUDIT
        | SYS_GETAUDIT_ADDR => {
            ctx.set_return(0);
        }

        SYS_GETPID | SYS_THREAD_SELFID => {
            ctx.set_return(1);
        }

        SYS_IOCTL => sys_ioctl(ctx),
        SYS_FCNTL => {
            ctx.set_return(if ctx.arg(1) == 3 { 2 } else { 0 });
        }
        SYS_MMAP => sys_mmap(ctx),
        SYS_SYSCTL => sys_sysctl(ctx),

        SYS_GETTIMEOFDAY => {
            let tv = ctx.arg(0) as *mut u64;
            if !tv.is_null() {
                unsafe {
                    tv.write(0);
                    tv.add(1).cast::<u32>().write(0);
                }
            }
            ctx.set_return(0);
        }

        SYS_GETRUSAGE => {
            let ru = ctx.arg(1) as *mut u8;
            if !ru.is_null() {
                unsafe { core::ptr::write_bytes(ru, 0, 144) };
            }
            ctx.set_return(0);
        }

        SYS_GETRLIMIT => {
            let rl = ctx.arg(1) as *mut u64;
            if !rl.is_null() {
                unsafe {
                    rl.write(u64::MAX);
                    rl.add(1).write(u64::MAX);
                }
            }
            ctx.set_return(0);
        }

        SYS_STAT64 | SYS_LSTAT64 => sys_stat64(ctx),
        SYS_SHARED_REGION_CHECK_NP => {
            ctx.set_error(2);
        }

        SYS_FSTAT64 => sys_fstat64(ctx),
        SYS_GETENTROPY => sys_getentropy(ctx),

        SYS_SOCKET | SYS_CONNECT | SYS_SENDTO | SYS_RECVFROM | SYS_GETSOCKOPT => {
            ctx.set_error(38); // ENOSYS
        }

        SYS_SETITIMER
        | SYS_KQUEUE_WORKLOOP_CTL
        | SYS_WORK_INTERVAL_CTL
        | SYS_CHDIR
        | SYS_FCHDIR
        | SYS_PIPE => {
            ctx.set_return(0);
        }

        SYS_DUP => {
            ctx.set_return(ctx.arg(0));
        }

        SYS_DUP2 => {
            ctx.set_return(ctx.arg(1));
        }

        SYS_ABORT_WITH_PAYLOAD => {
            let ns = ctx.arg(0);
            let code = ctx.arg(1);
            let payload_sz = ctx.arg(3);
            let reason_ptr = ctx.arg(4) as *const u8;

            uart::write_str("\n*** xnu-rs user abort_with_payload: ns=");
            uart::write_hex_u64(ns);
            uart::write_str(" code=");
            uart::write_hex_u64(code);
            uart::write_str(" payload_sz=");
            uart::write_hex_u64(payload_sz);

            if !reason_ptr.is_null() {
                uart::write_str(" reason=\"");
                let mut offset = 0;
                while offset < 1024 {
                    let b = unsafe { reason_ptr.add(offset).read() };
                    if b == 0 {
                        break;
                    }
                    uart::write_byte(b);
                    offset += 1;
                }
                uart::write_str("\"");
            }
            uart::write_str(" ***\n");

            loop {
                core::hint::spin_loop();
            }
        }

        // Stubs for calls dyld/libSystem issues during startup.
        // 381 = __mac_syscall / sandbox_ms; 242 = proc_rlimit_control
        // 55  = ioctl variant; 0x37 = sendmsg/setsockopt area
        55 | 242 | 381 => {
            ctx.set_return(0);
        }

        _ => {
            uart::write_str("xnu-rs: bsd x16=");
            uart::write_hex_u64(nr);
            uart::write_str("\n");
            ctx.set_error(38); // ENOSYS
        }
    }
}

fn sys_read(ctx: &mut SyscallContext) {
    let fd = ctx.arg(0) as usize;
    let buf_ptr = ctx.arg(1) as *mut u8;
    let len = ctx.arg(2) as usize;

    uart::write_str("xnu-rs: sys_read fd=");
    uart::write_hex_u64(fd as u64);
    uart::write_str(" len=0x");
    uart::write_hex_u64(len as u64);

    if fd == 0 || fd == DEV_NULL_FD || fd == DEV_CONSOLE_FD {
        uart::write_str(" -> 0 (eof)\n");
        ctx.set_return(0);
        return;
    }

    if fd == DEV_URANDOM_FD {
        if !buf_ptr.is_null() {
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
            let mut seed = crate::arch::time_ticks();
            for b in buf.iter_mut() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            ctx.set_return(len as u64);
        } else {
            ctx.set_return(0);
        }
        uart::write_str(" -> (random)\n");
        return;
    }

    if fd == DEV_ZERO_FD {
        if !buf_ptr.is_null() {
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
            buf.fill(0);
            ctx.set_return(len as u64);
        } else {
            ctx.set_return(0);
        }
        uart::write_str(" -> (zeros)\n");
        return;
    }

    if buf_ptr.is_null() {
        uart::write_str(" -> EINVAL (null buf)\n");
        ctx.set_error(22); // EINVAL
        return;
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };

    let current_offset = {
        let fds = open_files().lock();
        if fd >= fds.len() {
            uart::write_str(" -> EBADF (out of range)\n");
            ctx.set_error(9); // EBADF
            return;
        }
        let Some(file) = &fds[fd] else {
            uart::write_str(" -> EBADF (not open)\n");
            ctx.set_error(9); // EBADF
            return;
        };
        file.seek_offset
    };

    uart::write_str(" offset=0x");
    uart::write_hex_u64(current_offset);

    match read_from_fd(fd, buf, current_offset) {
        Ok(read_len) => {
            let mut fds = open_files().lock();
            if let Some(file) = &mut fds[fd] {
                file.seek_offset += read_len as u64;
            }
            uart::write_str(" -> read_len=0x");
            uart::write_hex_u64(read_len as u64);
            uart::write_str("\n");
            ctx.set_return(read_len as u64);
        }
        Err(errno) => {
            uart::write_str(" -> error errno=");
            uart::write_hex_u64(errno);
            uart::write_str("\n");
            ctx.set_error(errno);
        }
    }
}

fn sys_pread(ctx: &mut SyscallContext) {
    let fd = ctx.arg(0) as usize;
    let buf_ptr = ctx.arg(1) as *mut u8;
    let len = ctx.arg(2) as usize;
    let offset = ctx.arg(3);

    uart::write_str("xnu-rs: sys_pread fd=");
    uart::write_hex_u64(fd as u64);
    uart::write_str(" len=0x");
    uart::write_hex_u64(len as u64);
    uart::write_str(" offset=0x");
    uart::write_hex_u64(offset);

    if buf_ptr.is_null() {
        uart::write_str(" -> EINVAL (null buf)\n");
        ctx.set_error(22); // EINVAL
        return;
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };

    match read_from_fd(fd, buf, offset) {
        Ok(read_len) => {
            uart::write_str(" -> read_len=0x");
            uart::write_hex_u64(read_len as u64);
            uart::write_str("\n");
            ctx.set_return(read_len as u64);
        }
        Err(errno) => {
            uart::write_str(" -> error errno=");
            uart::write_hex_u64(errno);
            uart::write_str("\n");
            ctx.set_error(errno);
        }
    }
}

fn sys_open(ctx: &mut SyscallContext) {
    let path_ptr = ctx.arg(0) as *const u8;
    let Some(path) = get_user_string(path_ptr) else {
        uart::write_str("xnu-rs: sys_open -> EINVAL (null/invalid path)\n");
        ctx.set_error(22); // EINVAL
        return;
    };

    uart::write_str("xnu-rs: sys_open path=\"");
    uart::write_str(&path);
    uart::write_str("\"");

    match path.as_str() {
        "/dev/null" => {
            uart::write_str(" -> fd=100\n");
            ctx.set_return(DEV_NULL_FD as u64);
            return;
        }
        "/dev/console" | "/dev/tty" | "/dev/stderr" | "/dev/stdout" | "/dev/stdin" => {
            uart::write_str(" -> fd=101 (console)\n");
            ctx.set_return(DEV_CONSOLE_FD as u64);
            return;
        }
        "/dev/urandom" | "/dev/random" => {
            uart::write_str(" -> fd=102 (urandom)\n");
            ctx.set_return(DEV_URANDOM_FD as u64);
            return;
        }
        "/dev/zero" => {
            uart::write_str(" -> fd=103 (zero)\n");
            ctx.set_return(DEV_ZERO_FD as u64);
            return;
        }
        _ => {}
    }

    if let Some((data_offset, data_size)) = crate::fs::xnrsfs::get_file_info(&path) {
        let mut fds = open_files().lock();
        let mut fd_idx = None;
        for (i, slot) in fds.iter().enumerate() {
            if slot.is_none() {
                fd_idx = Some(i);
                break;
            }
        }
        let fd = if let Some(idx) = fd_idx {
            idx
        } else {
            fds.push(None);
            fds.len() - 1
        };
        fds[fd] = Some(OpenFile {
            path,
            data_offset,
            data_size,
            seek_offset: 0,
        });
        uart::write_str(" -> fd=");
        uart::write_hex_u64(fd as u64);
        uart::write_str("\n");
        ctx.set_return(fd as u64);
    } else {
        uart::write_str(" -> ENOENT\n");
        ctx.set_error(2); // ENOENT
    }
}

fn sys_close(ctx: &mut SyscallContext) {
    let fd = ctx.arg(0) as usize;
    uart::write_str("xnu-rs: sys_close fd=");
    uart::write_hex_u64(fd as u64);

    let mut fds = open_files().lock();
    if fd < fds.len() && fds[fd].is_some() {
        fds[fd] = None;
        uart::write_str(" -> ok\n");
        ctx.set_return(0);
    } else if is_dev_fd(fd) {
        uart::write_str(" -> ok (devfs)\n");
        ctx.set_return(0);
    } else {
        uart::write_str(" -> EBADF\n");
        ctx.set_error(9); // EBADF
    }
}

fn sys_lseek(ctx: &mut SyscallContext) {
    let fd = ctx.arg(0) as usize;
    let offset = ctx.arg(1) as i64;
    let whence = ctx.arg(2) as i32;

    let mut fds = open_files().lock();
    if fd >= fds.len() {
        ctx.set_error(9); // EBADF
        return;
    }
    let Some(file) = &mut fds[fd] else {
        ctx.set_error(9); // EBADF
        return;
    };

    let new_offset = match whence {
        0 => offset,                           // SEEK_SET
        1 => file.seek_offset as i64 + offset, // SEEK_CUR
        2 => file.data_size as i64 + offset,   // SEEK_END
        _ => {
            ctx.set_error(22); // EINVAL
            return;
        }
    };

    if new_offset < 0 {
        ctx.set_error(22); // EINVAL
        return;
    }

    file.seek_offset = new_offset as u64;
    ctx.set_return(file.seek_offset);
}

fn sys_fstat64(ctx: &mut SyscallContext) {
    let fd = ctx.arg(0) as usize;
    let st = ctx.arg(1) as *mut u8;

    if st.is_null() {
        ctx.set_error(22); // EINVAL
        return;
    }

    let size = {
        let fds = open_files().lock();
        if fd >= fds.len() {
            ctx.set_error(9); // EBADF
            return;
        }
        if is_dev_fd(fd) {
            0
        } else if let Some(file) = &fds[fd] {
            file.data_size
        } else {
            ctx.set_error(9); // EBADF
            return;
        }
    };

    unsafe {
        core::ptr::write_bytes(st, 0, 144);
        let mode = if is_dev_fd(fd) {
            0x2000 | 0o666 // S_IFCHR | rw-rw-rw-
        } else {
            0x8000 | 0o755 // S_IFREG | rwxr-xr-x
        };
        core::ptr::write_unaligned(st.add(4).cast::<u16>(), mode);
        core::ptr::write_unaligned(st.add(96).cast::<u64>(), size);
        core::ptr::write_unaligned(st.add(112).cast::<u32>(), 4096);
    }
    ctx.set_return(0);
}

fn sys_stat64(ctx: &mut SyscallContext) {
    let path_ptr = ctx.arg(0) as *const u8;
    let st = ctx.arg(1) as *mut u8;

    let Some(path) = get_user_string(path_ptr) else {
        ctx.set_error(22); // EINVAL
        return;
    };

    if st.is_null() {
        ctx.set_error(22); // EINVAL
        return;
    }

    let size = if path == "/dev/null" {
        0
    } else if let Some((_, data_size)) = crate::fs::xnrsfs::get_file_info(&path) {
        data_size
    } else {
        ctx.set_error(2); // ENOENT
        return;
    };

    unsafe {
        core::ptr::write_bytes(st, 0, 144);
        let mode = if path == "/dev/null" {
            0x2000 | 0o666
        } else {
            0x8000 | 0o755
        };
        core::ptr::write_unaligned(st.add(4).cast::<u16>(), mode);
        core::ptr::write_unaligned(st.add(96).cast::<u64>(), size);
        core::ptr::write_unaligned(st.add(112).cast::<u32>(), 4096);
    }
    ctx.set_return(0);
}

#[allow(clippy::missing_const_for_fn)]
fn sys_ioctl(ctx: &mut SyscallContext) {
    if ctx.arg(1) == TIOCGWINSZ {
        let ws = ctx.arg(2) as *mut u16;
        if !ws.is_null() {
            unsafe {
                ws.write(24);
                ws.add(1).write(80);
                ws.add(2).write(0);
                ws.add(3).write(0);
            }
        }
    }
    ctx.set_return(0);
}

#[allow(clippy::cast_possible_truncation)]
fn sys_mmap(ctx: &mut SyscallContext) {
    // RAM region for identity-mapped QEMU virt: 0x4000_0000 .. 0xC000_0000 (2 GiB).
    const RAM_START: u64 = 0x4000_0000;
    const RAM_END: u64 = 0xC000_0000;

    let addr = ctx.arg(0);
    let len = ctx.arg(1);
    let prot = ctx.arg(2);
    let flags = ctx.arg(3);
    let fd = ctx.arg(4) as usize;
    let offset = ctx.arg(5);
    let aligned = (len + 0xFFF) & !0xFFF;

    uart::write_str("xnu-rs: sys_mmap addr=0x");
    uart::write_hex_u64(addr);
    uart::write_str(" len=0x");
    uart::write_hex_u64(len);
    uart::write_str(" prot=0x");
    uart::write_hex_u64(prot);
    uart::write_str(" flags=0x");
    uart::write_hex_u64(flags);
    uart::write_str(" fd=");
    uart::write_hex_u64(fd as u64);
    uart::write_str(" offset=0x");
    uart::write_hex_u64(offset);
    uart::write_str("\n");

    let dest = if flags & MAP_FIXED != 0 && addr != 0 {
        if addr < RAM_START || addr + aligned > RAM_END {
            uart::write_str("xnu-rs: sys_mmap MAP_FIXED addr 0x");
            uart::write_hex_u64(addr);
            uart::write_str(" outside RAM, returning ENOMEM\n");
            ctx.set_error(12); // ENOMEM
            return;
        }
        addr
    } else {
        let base = super::MMAP_BASE.load(core::sync::atomic::Ordering::Relaxed);
        let start = if base == 0 {
            super::MMAP_REGION_START
        } else {
            base
        };
        if start + aligned <= super::MMAP_REGION_END {
            super::MMAP_BASE.store(start + aligned, core::sync::atomic::Ordering::Relaxed);
            start
        } else {
            uart::write_str("xnu-rs: sys_mmap ENOMEM\n");
            ctx.set_error(12); // ENOMEM
            return;
        }
    };

    uart::write_str("xnu-rs: sys_mmap dest=0x");
    uart::write_hex_u64(dest);
    uart::write_str("\n");

    unsafe { core::ptr::write_bytes(dest as *mut u8, 0, aligned as usize) };

    if flags & MAP_ANON == 0 {
        let buf = unsafe { core::slice::from_raw_parts_mut(dest as *mut u8, len as usize) };
        match read_from_fd(fd, buf, offset) {
            Ok(read_len) => {
                if read_len < len as usize {
                    unsafe {
                        core::ptr::write_bytes(
                            (dest + read_len as u64) as *mut u8,
                            0,
                            len as usize - read_len,
                        );
                    }
                }
            }
            Err(errno) => {
                uart::write_str("xnu-rs: sys_mmap read_from_fd error errno=");
                uart::write_hex_u64(errno);
                uart::write_str("\n");
                ctx.set_error(errno);
                return;
            }
        }
    }

    ctx.set_return(dest);
}

#[allow(clippy::cast_possible_truncation)]
fn sys_writev(ctx: &mut SyscallContext) {
    let fd = ctx.arg(0);
    let iov = ctx.arg(1) as *const u64;
    let cnt = ctx.arg(2) as usize;
    let mut total: u64 = 0;
    if (fd == 1 || fd == 2) && !iov.is_null() && cnt <= 64 {
        for i in 0..cnt {
            let base = unsafe { iov.add(i * 2).read() } as *const u8;
            let len = unsafe { iov.add(i * 2 + 1).read() } as usize;
            if !base.is_null() && len <= 65536 {
                let bytes = unsafe { core::slice::from_raw_parts(base, len) };
                for &b in bytes {
                    uart::write_byte(b);
                }
                total += len as u64;
            }
        }
    }
    ctx.set_return(total);
}

#[allow(clippy::cast_possible_truncation)]
fn sys_getentropy(ctx: &mut SyscallContext) {
    let buf = ctx.arg(0) as *mut u8;
    let len = ctx.arg(1) as usize;
    if !buf.is_null() && len <= 256 {
        let mut seed = crate::arch::time_ticks();
        for i in 0..len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            unsafe { buf.add(i).write(seed as u8) };
        }
    }
    ctx.set_return(0);
}

fn sys_sysctl(ctx: &mut SyscallContext) {
    let mib = ctx.arg(0) as *const u32;
    #[allow(clippy::cast_possible_truncation)]
    let miblen = ctx.arg(1) as usize;
    let oldp = ctx.arg(2) as *mut u8;
    let oldlenp = ctx.arg(3) as *mut usize;

    if mib.is_null() || miblen == 0 {
        ctx.set_error(22);
        return;
    }
    let mib0 = unsafe { mib.read() };
    let mib1 = if miblen > 1 {
        unsafe { mib.add(1).read() }
    } else {
        0
    };

    match (mib0, mib1) {
        (CTL_KERN, KERN_OSTYPE) => sysctl_str(oldp, oldlenp, b"Darwin\0"),
        (CTL_KERN, KERN_OSRELEASE) => sysctl_str(oldp, oldlenp, b"23.0.0\0"),
        (CTL_KERN, KERN_VERSION) => sysctl_str(oldp, oldlenp, b"Darwin Kernel Version 23.0.0\0"),
        (CTL_KERN, KERN_MAXFILES) => sysctl_u32(oldp, oldlenp, 10_240),
        (CTL_KERN, KERN_ARGMAX) => sysctl_u32(oldp, oldlenp, 262_144),
        (CTL_KERN, KERN_OSREV) => sysctl_u32(oldp, oldlenp, 23_000_000),
        (CTL_KERN, KERN_MAXPROC) => sysctl_u32(oldp, oldlenp, 1_024),
        (CTL_HW, HW_NCPU) => sysctl_u32(oldp, oldlenp, 1),
        (CTL_HW, HW_BYTEORDER) => sysctl_u32(oldp, oldlenp, 1234),
        (CTL_HW, HW_PAGESIZE) => sysctl_u32(oldp, oldlenp, 4096),
        (CTL_HW, HW_PHYSMEM | HW_USERMEM) => sysctl_u32(oldp, oldlenp, 2_048 * 1024 * 1024),
        (CTL_HW, HW_MEMSIZE) => sysctl_u64(oldp, oldlenp, 2 * 1024 * 1024 * 1024),
        (CTL_HW, HW_CPU_FREQ) => sysctl_u32(oldp, oldlenp, 1_000_000_000),
        (CTL_HW, HW_CACHELINESIZE) => sysctl_u32(oldp, oldlenp, 64),
        (0, _) => {
            // CTL_UNSPEC = sysctl-by-name lookup; just return ENOENT quietly.
            ctx.set_error(2);
            return;
        }
        _ => {
            uart::write_str("xnu-rs: sysctl ");
            uart::write_hex_u64(u64::from(mib0));
            uart::write_str(".");
            uart::write_hex_u64(u64::from(mib1));
            uart::write_str("\n");
            ctx.set_error(2);
            return;
        }
    }
    ctx.set_return(0);
}

fn sysctl_str(oldp: *mut u8, oldlenp: *mut usize, s: &[u8]) {
    if !oldlenp.is_null() {
        unsafe { oldlenp.write(s.len()) };
    }
    if oldp.is_null() {
        return;
    }
    let avail = if oldlenp.is_null() {
        0
    } else {
        unsafe { oldlenp.read() }
    };
    let n = avail.min(s.len());
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), oldp, n) };
}

#[allow(clippy::missing_const_for_fn)]
fn sysctl_u32(oldp: *mut u8, oldlenp: *mut usize, val: u32) {
    if !oldlenp.is_null() {
        unsafe { oldlenp.write(4) };
    }
    if !oldp.is_null() {
        unsafe { core::ptr::write_unaligned(oldp.cast::<u32>(), val) };
    }
}

#[allow(clippy::missing_const_for_fn)]
fn sysctl_u64(oldp: *mut u8, oldlenp: *mut usize, val: u64) {
    if !oldlenp.is_null() {
        unsafe { oldlenp.write(8) };
    }
    if !oldp.is_null() {
        unsafe { core::ptr::write_unaligned(oldp.cast::<u64>(), val) };
    }
}
