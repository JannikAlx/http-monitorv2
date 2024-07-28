use aya_ebpf::maps::{HashMap, PerCpuArray, PerfEventArray};
use aya_ebpf::macros::map;
use http_monitor_common::{AcceptArgs, CloseArgs, ConnInfo, DataArgs, SocketCloseEvent, SocketDataEvent, SocketOpenEvent};

#[map]
pub static mut CONN_INFO_MAP: HashMap<u64, ConnInfo> = HashMap::with_max_entries(131072, 0);

#[map]
pub static mut ACTIVE_ACCEPT_ARGS_MAP: HashMap<u64, AcceptArgs> = HashMap::with_max_entries(1024, 0);

#[map]
pub static mut SOCKET_DATA_EVENTS: PerfEventArray<SocketDataEvent> = PerfEventArray::with_max_entries(1024, 0);

#[map]
pub static mut SOCKET_OPEN_EVENTS: PerfEventArray<SocketOpenEvent> = PerfEventArray::with_max_entries(1024, 0);

#[map]
pub static mut SOCKET_CLOSE_EVENTS: PerfEventArray<SocketCloseEvent> = PerfEventArray::with_max_entries(1024, 0);

#[map]
pub static mut ACTIVE_WRITE_ARGS_MAP: HashMap<u64, DataArgs> = HashMap::with_max_entries(1024, 0);

#[map]
pub static mut ACTIVE_READ_ARGS_MAP: HashMap<u64, DataArgs> = HashMap::with_max_entries(1024, 0);

#[map]
pub static mut ACTIVE_CLOSE_ARGS_MAP: HashMap<u64, CloseArgs> = HashMap::with_max_entries(1024, 0);

#[map]
pub static mut SOCKET_DATA_EVENT_BUFFER_HEAP: PerCpuArray<SocketDataEvent> = PerCpuArray::with_max_entries(1, 0);