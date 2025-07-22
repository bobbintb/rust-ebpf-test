use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use dirt_common::UnlinkEvent;

#[map]
pub static mut UNLINK_EVENTS: HashMap<u32, UnlinkEvent> =
    HashMap::<u32, UnlinkEvent>::with_max_entries(1024, 0);
