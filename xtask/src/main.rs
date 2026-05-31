use clap::{Parser, Subcommand};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions, format_volume};
use gpt::{GptConfig, disk::LogicalBlockSize, mbr::ProtectiveMBR, partition_types};
use object::{
    LittleEndian, Object,
    elf::PT_LOAD,
    macho::{
        CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, EntryPointCommand, LC_MAIN, LC_SEGMENT_64,
        MH_EXECUTE, MH_MAGIC_64, SegmentCommand64, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
    },
    read::elf::{ElfFile64, ProgramHeader},
};
use std::{
    env, fs, io,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const TARGET: &str = "aarch64-unknown-none";
const UEFI_TARGET: &str = "aarch64-unknown-uefi";
const APPLE_TARGET: &str = "aarch64-apple-darwin";
const KERNEL_NAME: &str = "kernel";
const LOADER_NAME: &str = "bootloader";
const IMAGE_SIZE: u64 = 256 * 1024 * 1024;
const ESP_PARTITION_SIZE: u64 = 224 * 1024 * 1024;
const QEMU_FIRMWARE_ENV: &str = "QEMU_EFI_FD";

#[derive(Parser)]
#[command(name = "cargo-xtask")]
#[command(about = "Automation tasks for the xnu-rs workspace", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long = "ide")]
    is_ide: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run cargo check across targets
    Check,
    /// Run clippy checks with strict warning denials
    Clippy {
        /// Catch trailing flags injected by IDE language servers
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra_args: Vec<String>,
    },
    /// Format all files and verify compliance
    Fmt,
    /// Build bootloader and kernel images
    BuildImage,
    /// Generate a root filesystem
    MakeRootfs {
        /// Trailing arguments for rootfs configuration
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra_args: Vec<String>,
    },
    /// Boot the OS image inside QEMU
    #[command(alias = "qemu")]
    Run,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // 3. Match against parsed variants
    let status = match cli.command {
        Commands::Check => check(),
        Commands::Clippy { extra_args } => clippy(&extra_args),
        Commands::Fmt => cargo(&["fmt", "--all", "--", "--check"]),
        Commands::BuildImage => build_image(),
        Commands::MakeRootfs { extra_args } => make_rootfs(&extra_args),
        Commands::Run => run_qemu(),
    };

    match status {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            if cli.is_ide {
                ExitCode::SUCCESS // Keeps Zed diagnostics updating live
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn cargo(args: &[&str]) -> io::Result<bool> {
    Command::new("cargo")
        .args(args)
        .status()
        .map(|status| status.success())
}

fn cargo_many(runs: &[&[&str]]) -> io::Result<bool> {
    for args in runs {
        if !cargo(args)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn check() -> io::Result<bool> {
    cargo_many(&[
        &["check", "-p", KERNEL_NAME, "--target", TARGET],
        &["check", "-p", LOADER_NAME, "--target", UEFI_TARGET],
        &["check", "-p", "zs-alloc", "--target", TARGET],
        &["check", "-p", "loader", "--target", TARGET],
        &["check", "-p", "hello", "--target", APPLE_TARGET],
        &["check", "-p", "xtask"],
    ])
}

fn build_userspace() -> io::Result<bool> {
    cargo(&[
        "build",
        "-p",
        "hello",
        "--target",
        APPLE_TARGET,
        "--release",
    ])
}

fn clippy(extra_args: &[String]) -> io::Result<bool> {
    // Convert Vec<String> to Vec<&str> for Command
    let extra_slices: Vec<&str> = extra_args.iter().map(|s| s.as_str()).collect();

    // Base arguments for our cross-compilation crates
    let mut kernel_args = vec!["clippy", "-p", KERNEL_NAME, "--target", TARGET];
    let mut bootloader_args = vec!["clippy", "-p", LOADER_NAME, "--target", UEFI_TARGET];
    let mut alloc_args = vec!["clippy", "-p", "zs-alloc", "--target", TARGET];
    let mut lib_loader_args = vec!["clippy", "-p", "loader", "--target", TARGET];
    let mut hello_args = vec!["clippy", "-p", "hello", "--target", APPLE_TARGET];
    let mut xtask_args = vec!["clippy", "-p", "xtask"];

    // Forward the raw JSON flag strings passed from rust-analyzer directly into the subprocesses
    kernel_args.extend(&extra_slices);
    bootloader_args.extend(&extra_slices);
    alloc_args.extend(&extra_slices);
    lib_loader_args.extend(&extra_slices);
    hello_args.extend(&extra_slices);
    xtask_args.extend(&extra_slices);

    cargo_many(&[
        &kernel_args,
        &bootloader_args,
        &alloc_args,
        &lib_loader_args,
        &hello_args,
        &xtask_args,
    ])
}

fn build_image() -> io::Result<bool> {
    if !cargo(&["build", "-p", LOADER_NAME, "--target", UEFI_TARGET])? {
        return Ok(false);
    }
    if !cargo(&["build", "-p", KERNEL_NAME, "--target", TARGET])? {
        return Ok(false);
    }

    let out_dir = PathBuf::from("target/qemu");
    let bundle_dir = out_dir.join("bundle");
    let esp_dir = out_dir.join("esp");
    let images_dir = out_dir.join("images");
    fs::create_dir_all(bundle_dir.join("EFI/BOOT"))?;
    fs::create_dir_all(&esp_dir)?;
    fs::create_dir_all(&images_dir)?;

    let kernel_elf = PathBuf::from("target")
        .join(TARGET)
        .join("debug")
        .join(KERNEL_NAME);
    let kernel_macho = bundle_dir.join("kernel.macho");
    let loader_efi = discover_efi_artifact(LOADER_NAME)?;

    fs::copy(&kernel_elf, bundle_dir.join("kernel.elf"))?;
    convert_elf_to_macho(&kernel_elf, &kernel_macho)?;
    fs::copy(&loader_efi, bundle_dir.join("EFI/BOOT/BOOTAA64.EFI"))?;

    let manifest = format!(
        concat!(
            "kernel = \"kernel.macho\"\n",
            "loader = \"EFI/BOOT/BOOTAA64.EFI\"\n",
            "target = \"{TARGET}\"\n",
            "boot = \"UEFI\"\n",
            "debugging = [\"radare2\", \"r2ghidra\"]\n"
        ),
        TARGET = TARGET,
    );
    fs::write(bundle_dir.join("MANIFEST.toml"), manifest)?;

    let esp_img = images_dir.join("esp.img");
    build_uefi_disk_image(&esp_img, &loader_efi, &kernel_macho)?;

    println!("image bundle: {}", bundle_dir.display());
    println!("ESP image: {}", esp_img.display());
    Ok(true)
}

fn build_uefi_disk_image(
    image_path: &Path,
    loader_efi: &Path,
    kernel_macho: &Path,
) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(image_path)?;
    file.set_len(IMAGE_SIZE)?;

    ProtectiveMBR::with_lb_size(
        u32::try_from((IMAGE_SIZE / 512).saturating_sub(1))
            .map_err(|_| io::Error::other("image too large for protective MBR"))?,
    )
    .overwrite_lba0(&mut file)
    .map_err(gpt_error)?;

    let mut disk = GptConfig::default()
        .writable(true)
        .logical_block_size(LogicalBlockSize::Lb512)
        .create_from_device(file, None)
        .map_err(gpt_error)?;

    let part_id = disk
        .add_partition("ESP", ESP_PARTITION_SIZE, partition_types::EFI, 0, None)
        .map_err(gpt_error)?;
    let partition = disk
        .partitions()
        .get(&part_id)
        .cloned()
        .ok_or_else(|| io::Error::other("missing GPT partition after creation"))?;

    disk.write_inplace().map_err(gpt_error)?;
    let file = disk.write().map_err(gpt_error)?;

    let start = partition
        .bytes_start(LogicalBlockSize::Lb512)
        .map_err(gpt_error)?;
    let len = partition
        .bytes_len(LogicalBlockSize::Lb512)
        .map_err(gpt_error)?;
    let mut partition_io = PartitionIo::new(file, start, len);

    format_volume(
        &mut partition_io,
        FormatVolumeOptions::new().fat_type(FatType::Fat32),
    )?;

    let fs = FileSystem::new(partition_io, FsOptions::new())?;
    populate_esp(&fs, loader_efi, kernel_macho)?;
    fs.unmount()?;

    Ok(())
}

fn populate_esp<T: io::Read + io::Write + io::Seek>(
    fs: &FileSystem<T>,
    loader_efi: &Path,
    kernel_macho: &Path,
) -> io::Result<()> {
    let root = fs.root_dir();
    root.create_dir("EFI")?;
    root.create_dir("EFI/BOOT")?;

    copy_into_fat_file(loader_efi, &mut root.create_file("EFI/BOOT/BOOTAA64.EFI")?)?;
    copy_into_fat_file(kernel_macho, &mut root.create_file("KERNEL")?)?;

    let mut startup = root.create_file("STARTUP.NSH")?;

    let command = "\\EFI\\BOOT\\BOOTAA64.EFI\r\n";
    let mut script_bytes: Vec<u8> = Vec::new();

    script_bytes.push(0xFF);
    script_bytes.push(0xFE);

    for c in command.encode_utf16() {
        script_bytes.extend_from_slice(&c.to_le_bytes());
    }

    io::Write::write_all(&mut startup, &script_bytes)?;

    Ok(())
}

fn copy_into_fat_file(src: &Path, dst: &mut impl io::Write) -> io::Result<u64> {
    let mut src_file = fs::File::open(src)?;
    io::copy(&mut src_file, dst)
}

fn gpt_error<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::other(err.to_string())
}

#[allow(clippy::too_many_lines)]
fn convert_elf_to_macho(src: &Path, dst: &Path) -> io::Result<()> {
    use std::mem;

    const SIZEOF_SEGMENT_COMMAND_64: usize = mem::size_of::<SegmentCommand64<LittleEndian>>();
    const SIZEOF_ENTRY_POINT_COMMAND: usize = mem::size_of::<EntryPointCommand<LittleEndian>>();

    let elf_bytes = fs::read(src)?;
    let elf = ElfFile64::<LittleEndian>::parse(&*elf_bytes)
        .map_err(|err| io::Error::other(err.to_string()))?;

    let endian = LittleEndian;
    let loadable: Vec<_> = elf
        .elf_program_headers()
        .iter()
        .filter(|header| header.p_type(endian) == PT_LOAD && header.p_memsz(endian) != 0)
        .collect();
    if loadable.is_empty() {
        return Err(io::Error::other("ELF image has no PT_LOAD segments"));
    }

    let sizeofcmds = loadable
        .len()
        .checked_mul(SIZEOF_SEGMENT_COMMAND_64)
        .and_then(|size| size.checked_add(SIZEOF_ENTRY_POINT_COMMAND))
        .ok_or_else(|| io::Error::other("Mach-O command size overflow"))?;
    let header_size = 32usize;
    let mut file_offset = align_usize(header_size + sizeofcmds, 0x1000)?;

    let mut layout = Vec::with_capacity(loadable.len());
    let mut text_base = None;
    for (index, header) in loadable.iter().enumerate() {
        file_offset = align_usize(file_offset, 0x1000)?;
        let p_flags = header.p_flags(endian);
        let segname = segment_name(index, p_flags);
        if segname == *b"__TEXT\0\0\0\0\0\0\0\0\0\0" {
            text_base = Some((header.p_vaddr(endian), file_offset as u64));
        }

        layout.push(MachSegmentLayout {
            segname,
            vmaddr: header.p_vaddr(endian),
            vmsize: header.p_memsz(endian),
            fileoff: file_offset as u64,
            filesize: header.p_filesz(endian),
            initprot: vm_prot(p_flags),
            maxprot: vm_prot(p_flags),
            source_offset: usize::try_from(header.p_offset(endian))
                .map_err(|_| io::Error::other("ELF offset overflow"))?,
        });

        let file_size = usize::try_from(header.p_filesz(endian))
            .map_err(|_| io::Error::other("ELF file size overflow"))?;
        file_offset = file_offset
            .checked_add(file_size)
            .ok_or_else(|| io::Error::other("Mach-O file size overflow"))?;
    }

    let (text_vmaddr, text_fileoff): (u64, u64) =
        text_base.ok_or_else(|| io::Error::other("ELF image has no executable text segment"))?;
    let entryoff = elf
        .entry()
        .checked_sub(text_vmaddr.saturating_sub(text_fileoff))
        .ok_or_else(|| io::Error::other("invalid ELF entry for Mach-O conversion"))?;

    let final_size = file_offset;
    let mut macho = vec![0_u8; final_size];
    let mut cursor = 0usize;

    write_u32(&mut macho, &mut cursor, MH_MAGIC_64);
    write_u32(&mut macho, &mut cursor, CPU_TYPE_ARM64);
    write_u32(&mut macho, &mut cursor, CPU_SUBTYPE_ARM64_ALL);
    write_u32(&mut macho, &mut cursor, MH_EXECUTE);
    write_u32(
        &mut macho,
        &mut cursor,
        u32::try_from(layout.len() + 1)
            .map_err(|_| io::Error::other("too many Mach-O commands"))?,
    );
    write_u32(
        &mut macho,
        &mut cursor,
        u32::try_from(sizeofcmds).map_err(|_| io::Error::other("Mach-O commands too large"))?,
    );
    write_u32(&mut macho, &mut cursor, 0x1);
    write_u32(&mut macho, &mut cursor, 0);

    for segment in &layout {
        write_u32(&mut macho, &mut cursor, LC_SEGMENT_64);
        write_u32(
            &mut macho,
            &mut cursor,
            u32::try_from(SIZEOF_SEGMENT_COMMAND_64)
                .map_err(|_| io::Error::other("bad segment command size"))?,
        );
        macho[cursor..cursor + 16].copy_from_slice(&segment.segname);
        cursor += 16;
        write_u64(&mut macho, &mut cursor, segment.vmaddr);
        write_u64(&mut macho, &mut cursor, segment.vmsize);
        write_u64(&mut macho, &mut cursor, segment.fileoff);
        write_u64(&mut macho, &mut cursor, segment.filesize);
        write_u32(&mut macho, &mut cursor, segment.maxprot);
        write_u32(&mut macho, &mut cursor, segment.initprot);
        write_u32(&mut macho, &mut cursor, 0);
        write_u32(&mut macho, &mut cursor, 0);
    }

    write_u32(&mut macho, &mut cursor, LC_MAIN);
    write_u32(
        &mut macho,
        &mut cursor,
        u32::try_from(SIZEOF_ENTRY_POINT_COMMAND)
            .map_err(|_| io::Error::other("bad entry command size"))?,
    );
    write_u64(&mut macho, &mut cursor, entryoff);
    write_u64(&mut macho, &mut cursor, 0);

    for segment in &layout {
        let src_start = segment.source_offset;
        let src_end = src_start
            .checked_add(
                usize::try_from(segment.filesize)
                    .map_err(|_| io::Error::other("Mach-O segment file size overflow"))?,
            )
            .ok_or_else(|| io::Error::other("Mach-O segment range overflow"))?;
        let dst_start = usize::try_from(segment.fileoff)
            .map_err(|_| io::Error::other("Mach-O file offset overflow"))?;
        let dst_end = dst_start
            .checked_add(src_end - src_start)
            .ok_or_else(|| io::Error::other("Mach-O output range overflow"))?;
        macho[dst_start..dst_end].copy_from_slice(&elf_bytes[src_start..src_end]);
    }

    fs::write(dst, macho)
}

fn segment_name(index: usize, flags: u32) -> [u8; 16] {
    const TEXT: [u8; 16] = *b"__TEXT\0\0\0\0\0\0\0\0\0\0";
    const DATA: [u8; 16] = *b"__DATA\0\0\0\0\0\0\0\0\0\0";
    if flags & 0x1 != 0 {
        TEXT
    } else if flags & 0x2 != 0 {
        DATA
    } else {
        let mut name = [0_u8; 16];
        let label = format!("__SEG{index}");
        let bytes = label.as_bytes();
        name[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        name
    }
}

const fn vm_prot(flags: u32) -> u32 {
    let mut prot = 0;
    if flags & 0x4 != 0 {
        prot |= VM_PROT_READ;
    }
    if flags & 0x2 != 0 {
        prot |= VM_PROT_WRITE;
    }
    if flags & 0x1 != 0 {
        prot |= VM_PROT_EXECUTE;
    }
    prot
}

fn align_usize(value: usize, align: usize) -> io::Result<usize> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| io::Error::other("alignment overflow"))
}

fn write_u32(buf: &mut [u8], cursor: &mut usize, value: u32) {
    buf[*cursor..*cursor + 4].copy_from_slice(&value.to_le_bytes());
    *cursor += 4;
}

fn write_u64(buf: &mut [u8], cursor: &mut usize, value: u64) {
    buf[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
    *cursor += 8;
}

fn discover_efi_artifact(name: &str) -> io::Result<PathBuf> {
    let deps_dir = PathBuf::from("target")
        .join(UEFI_TARGET)
        .join("debug")
        .join("deps");
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;

    for entry in fs::read_dir(&deps_dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_efi = path.extension().and_then(|ext| ext.to_str()) == Some("efi");
        let matches_name = path
            .file_name()
            .and_then(|file| file.to_str())
            .is_some_and(|file| file.starts_with(name) || file.contains(&format!("{name}-")));
        if !(is_efi && matches_name) {
            continue;
        }

        let modified = entry
            .metadata()?
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let replace = best
            .as_ref()
            .is_none_or(|(best_time, _)| modified > *best_time);
        if replace {
            best = Some((modified, path));
        }
    }

    best.map(|(_, path)| path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("could not locate {name}.efi in {}", deps_dir.display()),
        )
    })
}

fn qemu_firmware_path() -> io::Result<PathBuf> {
    if let Ok(path) = env::var(QEMU_FIRMWARE_ENV) {
        return Ok(PathBuf::from(path));
    }

    for candidate in [
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/opt/homebrew/opt/qemu/share/qemu/edk2-aarch64-code.fd",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "UEFI firmware not found; set QEMU_EFI_FD",
    ))
}

/// Build a rootfs disk image in the xnrsfs flat format.
///
/// Usage: `cargo xtask make-rootfs [file:path/on/disk] ...`
///
/// Each argument is `name:host_path`. The image is written to
/// `target/qemu/images/rootfs.img`.
///
/// xnrsfs layout (all little-endian):
///   Bytes  0–3:  magic = 0x53524E58 ("XNRS")
///   Bytes  4–7:  file count (u32)
///   Bytes  8–(8+count*80): file table entries:
///     [64]: null-terminated name
///     [ 8]: data offset (u64) from start of image
///     [ 8]: data size (u64)
///   Remainder: file data at 4096-byte aligned offsets
#[allow(clippy::too_many_lines, clippy::collapsible_if)]
fn make_rootfs(file_args: &[String]) -> io::Result<bool> {
    const MAGIC: u32 = 0x5352_4E58; // "XNRS" LE
    const ENTRY_SIZE: usize = 80; // 64 name + 8 offset + 8 size
    const ALIGN: u64 = 4096;

    let out_dir = Path::new("target/qemu/images");
    fs::create_dir_all(out_dir)?;
    let out_path = out_dir.join("rootfs.img");

    // Parse arguments: "virtname:hostpath"
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for arg in file_args {
        let Some((name, host)) = arg.split_once(':') else {
            eprintln!("make-rootfs: bad arg '{arg}' (expected name:path)");
            return Ok(false);
        };
        files.push((name.to_string(), PathBuf::from(host)));
    }

    if files.is_empty() {
        // Default: build and embed the workspace hello binary.
        if !build_userspace()? {
            return Ok(false);
        }
        let hello_path = PathBuf::from("target")
            .join(APPLE_TARGET)
            .join("release")
            .join("hello");
        if !hello_path.exists() {
            eprintln!(
                "make-rootfs: hello binary not found at {}",
                hello_path.display()
            );
            return Ok(false);
        }
        files.push(("/bin/hello".to_string(), hello_path));
    }

    let count = files.len();
    let table_bytes = count * ENTRY_SIZE;
    let header_bytes = 8 + table_bytes; // 4 magic + 4 count + table

    // Compute per-file aligned offsets.
    let mut offsets: Vec<u64> = Vec::with_capacity(count);
    let mut next_offset = ((header_bytes as u64) + ALIGN - 1) & !(ALIGN - 1);
    let mut sizes: Vec<u64> = Vec::with_capacity(count);
    for (_, host_path) in &files {
        offsets.push(next_offset);
        let sz = fs::metadata(host_path).map_or(0, |m| m.len());
        sizes.push(sz);
        next_offset = (next_offset + sz + ALIGN - 1) & !(ALIGN - 1);
    }
    let total = next_offset;

    println!(
        "make-rootfs: creating {} ({total} bytes, {count} files)",
        out_path.display(),
    );

    // Write the image.
    let mut img = fs::File::create(&out_path)?;

    // Header: magic + count.
    img.write_all(&MAGIC.to_le_bytes())?;
    img.write_all(&u32::try_from(count).unwrap_or(0).to_le_bytes())?;

    // File table.
    for i in 0..count {
        let mut name_buf = [0u8; 64];
        let name_bytes = files[i].0.as_bytes();
        let copy_len = name_bytes.len().min(63);
        name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        img.write_all(&name_buf)?;
        img.write_all(&offsets[i].to_le_bytes())?;
        img.write_all(&sizes[i].to_le_bytes())?;
    }

    // Pad to first file offset.
    let header_end = 8 + table_bytes;
    let pad_to = usize::try_from(offsets[0]).unwrap_or(0);
    if pad_to > header_end {
        let pad = vec![0u8; pad_to - header_end];
        img.write_all(&pad)?;
    }

    // Write each file with alignment padding.
    for i in 0..count {
        let (_, host_path) = &files[i];
        print!("  adding {} ({} bytes)... ", host_path.display(), sizes[i]);
        std::io::stdout().flush()?;

        let mut file = fs::File::open(host_path)?;
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut bytes_written = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            img.write_all(&buffer[..n])?;
            bytes_written += n as u64;
        }

        // Pad to next alignment.
        let next = if i + 1 < count { offsets[i + 1] } else { total };
        let written = offsets[i] + bytes_written;
        if next > written {
            let pad = vec![0u8; usize::try_from(next - written).unwrap_or(0)];
            img.write_all(&pad)?;
        }
        println!("ok");
    }

    println!("make-rootfs: done → {}", out_path.display());
    Ok(true)
}

fn run_qemu() -> io::Result<bool> {
    if !build_image()? {
        return Ok(false);
    }
    // Always rebuild the rootfs so the latest hello binary is embedded.
    if !make_rootfs(&[])? {
        return Ok(false);
    }
    let firmware = qemu_firmware_path()?;
    let rootfs_path = "target/qemu/images/rootfs.img";
    let mut cmd = Command::new("qemu-system-aarch64");
    cmd.args([
        "-M",
        "virt,virtualization=on",
        "-accel",
        "tcg,thread=multi",
        "-cpu",
        "max",
        "-smp",
        "4",
        "-m",
        "2048M",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-bios",
    ])
    .arg(firmware)
    // ESP (UEFI boot + kernel) via virtio-pci — UEFI finds this.
    .args([
        "-drive",
        "if=virtio,format=raw,file=target/qemu/images/esp.img",
    ]);
    // Rootfs via virtio-mmio — kernel finds this at 0x0a000000.
    if std::path::Path::new(rootfs_path).exists() {
        cmd.args([
            "-drive",
            &format!("id=rootfs,if=none,format=raw,file={rootfs_path}"),
            "-device",
            "virtio-blk-device,drive=rootfs",
        ]);
    }
    let status = cmd.status()?;
    Ok(status.success())
}

struct MachSegmentLayout {
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    source_offset: usize,
}

struct PartitionIo<T> {
    inner: T,
    base: u64,
    len: u64,
    pos: u64,
}

impl<T> PartitionIo<T> {
    const fn new(inner: T, base: u64, len: u64) -> Self {
        Self {
            inner,
            base,
            len,
            pos: 0,
        }
    }
}

impl<T: io::Read + io::Write + io::Seek> io::Read for PartitionIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = self.len - self.pos;
        let max = u64::try_from(buf.len()).map_err(|_| io::Error::other("buffer too large"))?;
        let count =
            usize::try_from(remaining.min(max)).map_err(|_| io::Error::other("read overflow"))?;
        self.inner.seek(io::SeekFrom::Start(self.base + self.pos))?;
        let read = self.inner.read(&mut buf[..count])?;
        self.pos += u64::try_from(read).map_err(|_| io::Error::other("read overflow"))?;
        Ok(read)
    }
}

impl<T: io::Read + io::Write + io::Seek> io::Write for PartitionIo<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = self.len - self.pos;
        let max = u64::try_from(buf.len()).map_err(|_| io::Error::other("buffer too large"))?;
        let count =
            usize::try_from(remaining.min(max)).map_err(|_| io::Error::other("write overflow"))?;
        self.inner.seek(io::SeekFrom::Start(self.base + self.pos))?;
        let written = self.inner.write(&buf[..count])?;
        self.pos += u64::try_from(written).map_err(|_| io::Error::other("write overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: io::Read + io::Write + io::Seek> io::Seek for PartitionIo<T> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let next = match pos {
            io::SeekFrom::Start(off) => off,
            io::SeekFrom::Current(delta) => if delta >= 0 {
                self.pos.checked_add(
                    u64::try_from(delta).map_err(|_| io::Error::other("seek overflow"))?,
                )
            } else {
                self.pos.checked_sub(delta.unsigned_abs())
            }
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside partition"))?,
            io::SeekFrom::End(delta) => if delta >= 0 {
                self.len.checked_add(
                    u64::try_from(delta).map_err(|_| io::Error::other("seek overflow"))?,
                )
            } else {
                self.len.checked_sub(delta.unsigned_abs())
            }
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside partition"))?,
        };

        if next > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside partition",
            ));
        }

        self.pos = next;
        Ok(self.pos)
    }
}
