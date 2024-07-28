#![no_std]

use aya_ebpf;
use aya_ebpf_bindings::bindings::sockaddr;

pub const MAX_MSG_SIZE: usize = 30720;
pub const CHUNK_LIMIT: usize = 4;
pub struct DataOut {
    pub data: [u8; 5],
    pub len: u32,
}

// A struct representing a unique ID that is composed of the pid, the file
// descriptor and the creation time of the struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnId {
    // Process ID
    pub pid: u32,
    // The file descriptor to the opened network connection.
    pub fd: i32,
    pub creation_time: u64,
}


// This struct contains information collected when a connection is established,
// via an accept4() syscall.
#[repr(C)]
pub struct ConnInfo {
    // Connection identifier.
    pub conn_id: ConnId,
    // The number of bytes written/read on this connection.
    pub wr_bytes: u64,
    pub rd_bytes: u64,
    // A flag indicating we identified the connection as HTTP.
    pub is_http: bool
}

// An helper struct that hold the addr argument of the syscall.
#[repr(C)]
pub struct AcceptArgs {
    pub addr: sockaddr,
}

// An helper struct to cache input argument of read/write syscalls between the
// entry hook and the exit hook.
#[repr(C)]
pub struct DataArgs {
    pub fd: i32,
    pub buf: *const u8,
}

#[repr(C)]
pub struct CloseArgs {
    pub fd: i32,
}

#[repr(C)]
pub struct SocketOpenEvent {
    pub timestamp_ns: u64,
    pub conn_id: ConnId,
    pub addr: sockaddr
}

#[repr(C)]
pub struct SocketCloseEvent {
    pub timestamp_ns: u64,
    pub conn_id: ConnId,

    // The number of bytes written/read on this connection.
    pub wr_bytes: u64,
    pub rd_bytes: u64
}

#[derive(Clone, Copy)]
pub enum  TrafficDirection {
    IN,
    OUT
}

pub struct Attributes {
    pub timestamp: u64,
    pub conn_id: ConnId,

    // The type of the actual data that the msg field encodes, which is used by the caller
    // to determine how to interpret the data.
    pub traffic_direction: TrafficDirection,

    // The size of the original message. We use this to truncate msg field to minimize the amount
    // of data being transferred.
    pub msg_size: u32,
    // A 0-based position number for this event on the connection, in terms of byte position.
    // The position is for the first byte of this message.
    pub pos: u64
}

#[repr(C)]
pub struct SocketDataEvent {
    pub attributes: Attributes,
    pub msg: [u8; MAX_MSG_SIZE]
}

pub type __u16 = ::aya_ebpf::cty::c_ushort;
pub type __be16 = __u16;
pub type __kernel_sa_family_t = ::aya_ebpf::cty::c_ushort;
pub type __u32 = ::aya_ebpf::cty::c_uint;
pub type __be32 = __u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_addr {
    pub s_addr: __be32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: __kernel_sa_family_t,
    pub sin_port: __be16,
    pub sin_addr: in_addr,
    pub __pad: [::aya_ebpf::cty::c_uchar; 8usize],
}
