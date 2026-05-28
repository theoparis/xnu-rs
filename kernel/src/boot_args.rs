const BOOT_LINE_LENGTH: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct BootVideo {
    pub v_base_addr: u64,
    pub v_display: u64,
    pub v_row_bytes: u64,
    pub v_width: u64,
    pub v_height: u64,
    pub v_depth: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct BootArgs {
    pub revision: u16,
    pub version: u16,
    pub virt_base: u64,
    pub phys_base: u64,
    pub mem_size: u64,
    pub top_of_kernel_data: u64,
    pub video: BootVideo,
    pub machine_type: u32,
    pub device_tree_p: *const core::ffi::c_void,
    pub device_tree_length: u32,
    pub command_line: [u8; BOOT_LINE_LENGTH],
    pub boot_flags: u64,
    pub mem_size_actual: u64,
}
