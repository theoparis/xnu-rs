#![allow(clippy::redundant_pub_crate)]

const BOOT_LINE_LENGTH: usize = 1024;
const KBOOT_ARGS_REVISION2: u16 = 2;
const KBOOT_ARGS_VERSION2: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub(crate) struct BootVideo {
    pub(crate) v_base_addr: u64,
    pub(crate) v_display: u64,
    pub(crate) v_row_bytes: u64,
    pub(crate) v_width: u64,
    pub(crate) v_height: u64,
    pub(crate) v_depth: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub(crate) struct BootArgs {
    pub(crate) revision: u16,
    pub(crate) version: u16,
    pub(crate) virt_base: u64,
    pub(crate) phys_base: u64,
    pub(crate) mem_size: u64,
    pub(crate) top_of_kernel_data: u64,
    pub(crate) video: BootVideo,
    pub(crate) machine_type: u32,
    pub(crate) device_tree_p: *const core::ffi::c_void,
    pub(crate) device_tree_length: u32,
    pub(crate) command_line: [u8; BOOT_LINE_LENGTH],
    pub(crate) boot_flags: u64,
    pub(crate) mem_size_actual: u64,
}

impl BootArgs {
    pub(crate) const fn zeroed() -> Self {
        Self {
            revision: KBOOT_ARGS_REVISION2,
            version: KBOOT_ARGS_VERSION2,
            virt_base: 0,
            phys_base: 0,
            mem_size: 0,
            top_of_kernel_data: 0,
            video: BootVideo {
                v_base_addr: 0,
                v_display: 0,
                v_row_bytes: 0,
                v_width: 0,
                v_height: 0,
                v_depth: 0,
            },
            machine_type: 0,
            device_tree_p: core::ptr::null(),
            device_tree_length: 0,
            command_line: [0; BOOT_LINE_LENGTH],
            boot_flags: 0,
            mem_size_actual: 0,
        }
    }
}
