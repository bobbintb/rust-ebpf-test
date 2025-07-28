#[repr(C)]
#[derive(Copy, Clone)]
pub struct unlinkat_args {
    pub dfd: ::aya_ebpf::cty::c_int,
    pub pathname: *const ::aya_ebpf::cty::c_char,
    pub flags: ::aya_ebpf::cty::c_int,
}
