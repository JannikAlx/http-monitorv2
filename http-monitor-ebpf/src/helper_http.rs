use core::ops::Deref;
use core::ptr::read_unaligned;
use core::str::{from_raw_parts, from_utf8_unchecked};
use aya_ebpf::bindings::__u32;
use aya_ebpf_cty::c_void;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_retval, bpf_ktime_get_ns, bpf_map_update_elem};
use aya_ebpf::helpers::gen::{bpf_probe_read, bpf_probe_read_user};
use aya_ebpf::memset;
use aya_ebpf::programs::{RawTracePointContext, TracePointContext};
use aya_log_ebpf::{error, info, warn};
use http_monitor_common::{AcceptArgs, Attributes, CHUNK_LIMIT, CloseArgs, ConnId, ConnInfo, DataArgs, MAX_MSG_SIZE, SocketCloseEvent, SocketDataEvent, SocketOpenEvent, TrafficDirection};
use crate::maps_http::{CONN_INFO_MAP, SOCKET_CLOSE_EVENTS, SOCKET_DATA_EVENT_BUFFER_HEAP, SOCKET_DATA_EVENTS, SOCKET_OPEN_EVENTS};

#[inline]
pub fn gen_tgid_fd(pid: u32, ret_fd: u32) -> u64 {
    ((pid as u64) << 32) | (ret_fd as u64)
}

#[inline]
pub fn is_http_connection(conn_info: &ConnInfo, buf: [u8; 16], byte_count: isize) -> bool {
    if conn_info.is_http == 1 {
        return true;
    }
    unsafe {
        if byte_count < 16 {
            return false;
        }
        let mut res = false;

        let str_buf = from_utf8_unchecked(&buf);
        if str_buf.starts_with("HTTP") {
            res = true;
        }
        if str_buf.starts_with("GET") {
            res = true;
        }
        if str_buf.starts_with("POST") {
            res = true;
        }
        res
    }
}

#[inline]
pub fn perf_submit_buf(ctx: &TracePointContext, direction: TrafficDirection, buf: &[u8], conn_info: &ConnInfo, event: &mut SocketDataEvent, offset: usize, pid_fd: u64) {

    let new_conn_info = &mut ConnInfo {
        conn_id: conn_info.conn_id,
        wr_bytes: conn_info.wr_bytes,
        rd_bytes: conn_info.rd_bytes,
        is_http: 1,
    };

    match direction {

        TrafficDirection::IN => {
            event.attributes.pos = new_conn_info.wr_bytes + offset as u64;
        }
        TrafficDirection::OUT => {
            event.attributes.pos = new_conn_info.rd_bytes + offset as u64;
        }
    }

    let buff_size_minus_1 = buf.len() - 1;

    // TODO Check if we need to update this?
    let mut amount_copied: usize = 0;

    if buff_size_minus_1 < MAX_MSG_SIZE {
        event.msg[..buf.len()].copy_from_slice(buf);
        amount_copied = buf.len();
    } else {
        event.msg[..MAX_MSG_SIZE].copy_from_slice(&buf[..MAX_MSG_SIZE]);
        amount_copied = MAX_MSG_SIZE;
    }
    unsafe {
        if amount_copied > 0 {
            event.attributes.msg_size = amount_copied as u32;
            SOCKET_DATA_EVENTS.output(ctx, &event, 0)
        }
        CONN_INFO_MAP.insert(&pid_fd, &new_conn_info, 0).unwrap();
    }
}

#[inline]
fn perf_submit_wrapper(
    ctx: &TracePointContext,
    direction: TrafficDirection,
    buf: *const u8,
    buf_size: usize,
    conn_info: &mut ConnInfo,
    event: &mut SocketDataEvent,
    pid_fd: u64,
) {
    let mut bytes_sent = 0;

    for i in 0..CHUNK_LIMIT {
        let bytes_remaining = buf_size - bytes_sent;
        let current_size = if bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1) {
            MAX_MSG_SIZE
        } else {
            bytes_remaining
        };

        let mut buf_to_be_read = [0u8; MAX_MSG_SIZE];
        unsafe {
            bpf_probe_read(buf_to_be_read.as_mut_ptr() as *mut _, current_size as __u32, buf.add(bytes_sent) as *const _);
        }
        perf_submit_buf(ctx, direction, &buf[bytes_sent..bytes_sent + current_size], conn_info, event, bytes_sent, pid_fd);
        bytes_sent += current_size;

        if buf_size == bytes_sent {
            return;
        }
    }
}



#[inline]
pub fn process_syscall_accept(ctx: &TracePointContext, id: u64, args: &AcceptArgs) {
    // Implement the logic to process accept syscall

    unsafe {
        // offset is return fd, idk from where I have this, but it works
        let ret_fd = ctx.read_at(16).unwrap_or_default();
        if ret_fd <= 0 {
            return;
        }
        //let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;??
        // let pid = bpf_get_current_pid_tgid() as u32;
        let pid: u32 = (id >> 32) as u32;
        let conn_id_p = ConnId {
            pid,
            fd: ret_fd,
            creation_time: bpf_ktime_get_ns(),
        };

        let conn_info = ConnInfo {
            conn_id: conn_id_p,
            wr_bytes: 0,
            rd_bytes: 0,
            is_http: 0,
        };

        let pid = (id >> 32) as u32;
        let pid_fd = gen_tgid_fd(pid, ret_fd);
        CONN_INFO_MAP.insert(&pid_fd, &conn_info, 0).unwrap();

        if let Some(inserted_conn_info) = CONN_INFO_MAP.get(&pid_fd) {} else {
            error!(ctx, "Failed to insert conn info for key: {}", pid_fd);
        }

        let open_event = SocketOpenEvent {
            timestamp_ns: bpf_ktime_get_ns(),
            conn_id: conn_id_p,
            addr: args.addr,
        };
        SOCKET_OPEN_EVENTS.output(ctx, &open_event, 0);
    }
}

pub fn process_syscall_close(ctx: &TracePointContext, id: u64, args: &CloseArgs) {
    unsafe {
        info!(ctx, "Processing close syscall");
        let ret_val: u32 = ctx.read_at(16).unwrap_or_default();
        if ret_val < 0 {
            return;
        }

        let tgid = (id >> 32) as u32;
        let tgid_fd = gen_tgid_fd(tgid, args.fd);
        let conn_info = match CONN_INFO_MAP.get(&tgid_fd) {
            Some(conn_info) => conn_info,
            // Ignore if the connection info is not found
            None => return
        };

        //Send userspace event
        let close_event = SocketCloseEvent {
            timestamp_ns: bpf_ktime_get_ns(),
            conn_id: conn_info.conn_id,
            wr_bytes: conn_info.wr_bytes,
            rd_bytes: conn_info.rd_bytes,
        };

        SOCKET_CLOSE_EVENTS.output(ctx, &close_event, 0);
        info!(ctx, "output close event");
        CONN_INFO_MAP.remove(&tgid_fd).unwrap()
    }
}

pub fn process_data(ctx: &TracePointContext, id: u64, direction: TrafficDirection, args: &DataArgs, bytes_count: isize) {
    if args.buf.is_null() {
        error!(ctx, "Null buffer");
        return;
    }

    if bytes_count <= 0 {
        return;
    }
    unsafe {
        let pid = (id >> 32) as u32;
        let pid_fd = gen_tgid_fd(pid, args.fd);
        //info!(ctx, "Accessing conn pid_fd: {}", pid_fd);

        let conn_info_retrieved = CONN_INFO_MAP.get(&pid_fd);
        if conn_info_retrieved.is_none() {
            //warn!(ctx, "Failed to get conn info for key: {}", pid_fd);
            return;
        }
        let conn_info = conn_info_retrieved.unwrap();

        //info!(ctx, "Accessing conn pid: {}", conn_info.conn_id.pid);
        let mut buf_read = [0u8; 16];
        bpf_probe_read_user(
            &mut buf_read as *mut _ as *mut _,
            7,
            args.buf as *const _,
        );
        if is_http_connection(conn_info, buf_read, bytes_count) {
            let comm = bpf_get_current_comm().unwrap();
            let comm_name = from_utf8_unchecked(&comm);
            info!(ctx, "HTTP connection detected for comm: {}", comm_name);
            let k_zero: u32 = 0;

            let mut event: &mut SocketDataEvent = &mut SocketDataEvent {
                attributes: Attributes {
                    timestamp: bpf_ktime_get_ns(),
                    conn_id: conn_info.conn_id,
                    traffic_direction: direction,
                    msg_size: 0,
                    pos: 0,
                },
                msg: [0u8; MAX_MSG_SIZE],
            };

            perf_submit_wrapper(ctx, direction, args.buf, bytes_count as usize, conn_info, event, pid_fd);
        }
        let mut new_conn_info = ConnInfo {
            conn_id: conn_info.conn_id,
            wr_bytes: conn_info.wr_bytes,
            rd_bytes: conn_info.rd_bytes,
            is_http: 1,
        };
        match direction {
            TrafficDirection::OUT => new_conn_info.wr_bytes += bytes_count as u64,
            TrafficDirection::IN => new_conn_info.rd_bytes += bytes_count as u64,
        }
        // Update the connection info
        let res = CONN_INFO_MAP.insert(&pid_fd, &conn_info, 0);
        if res.is_err() {
            error!(ctx, "Failed to update connection info");
        }
    }
}