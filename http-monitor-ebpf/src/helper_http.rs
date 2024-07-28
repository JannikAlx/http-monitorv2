use core::ops::Deref;
use core::str::from_raw_parts;
use aya_ebpf::bindings::__u32;
use aya_ebpf_cty::c_void;
use aya_ebpf::helpers::{bpf_get_retval, bpf_ktime_get_ns};
use aya_ebpf::helpers::gen::bpf_probe_read;
use aya_ebpf::programs::{RawTracePointContext, TracePointContext};
use aya_log_ebpf::error;
use http_monitor_common::{AcceptArgs, Attributes, CHUNK_LIMIT, CloseArgs, ConnId, ConnInfo, DataArgs, MAX_MSG_SIZE, SocketCloseEvent, SocketDataEvent, SocketOpenEvent, TrafficDirection};
use crate::maps_http::{CONN_INFO_MAP, SOCKET_CLOSE_EVENTS, SOCKET_DATA_EVENT_BUFFER_HEAP, SOCKET_DATA_EVENTS, SOCKET_OPEN_EVENTS};

#[inline]
fn gen_tgid_fd(tgid: u32, fd: i32) -> u64 {
    ((tgid as u64) << 32) | (fd as u64)
}

#[inline]
fn is_http_connection(conn_info: &mut ConnInfo, buf: &[u8]) -> bool {
    //TODO: check if we have an actual buffer, or just a pointer
    if conn_info.is_http {
        return true;
    }

    if buf.len() < 16 {
        return false;
    }
    let mut res = false;

    let http = "HTTP".as_bytes();
    let get = "GET".as_bytes();
    let post = "POST".as_bytes();
    if buf[0..3].eq(http) { res = true; }
    if buf[0..2].eq(get) { res = true; }
    if buf[0..4].eq(post) { res = true; }

    if res {
        conn_info.is_http = true;
    }

    res
}

#[inline]
fn perf_submit_buf(ctx: &TracePointContext, direction: TrafficDirection, buf: &[u8], conn_info: &ConnInfo, event: &mut SocketDataEvent, offset: usize) {
    match direction {
        TrafficDirection::IN => {
            event.attributes.pos = conn_info.wr_bytes + offset as u64;
        }
        TrafficDirection::OUT => {
            event.attributes.pos = conn_info.rd_bytes + offset as u64;
        }
    }

    let buff_size_minus_1 = buf.len() - 1;

    // TODO Check if we need to update this?
    let mut amount_copied: usize = 0;

    if buff_size_minus_1 < MAX_MSG_SIZE {
        event.msg[..buf.len()].copy_from_slice(buf);
        amount_copied = buf.len();
    }
    else {
        event.msg[..MAX_MSG_SIZE].copy_from_slice(&buf[..MAX_MSG_SIZE]);
        amount_copied = MAX_MSG_SIZE;
    }
    unsafe {
        if amount_copied > 0 {
            event.attributes.msg_size = amount_copied as u32;
            SOCKET_DATA_EVENTS.output(ctx, &event, 0)
        }
    }

}

#[inline]
fn perf_submit_wrapper(
    ctx: &TracePointContext,
    direction: TrafficDirection,
    buf: &[u8],
    buf_size: usize,
    conn_info: &mut ConnInfo,
    event: &mut SocketDataEvent,
) {
    let mut bytes_sent = 0;

    for i in 0..CHUNK_LIMIT {
        let bytes_remaining = buf_size - bytes_sent;
        let current_size = if bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1) {
            MAX_MSG_SIZE
        } else {
            bytes_remaining
        };

        perf_submit_buf(ctx, direction, &buf[bytes_sent..bytes_sent + current_size], conn_info, event, bytes_sent);
        bytes_sent += current_size;

        if buf_size == bytes_sent {
            return;
        }
    }
}

#[inline]
pub fn process_syscall_accept(ctx: &RawTracePointContext, id: u64, args: &AcceptArgs) {
    // Implement the logic to process accept syscall

    unsafe {
        let ret_fd = bpf_get_retval();
        if ret_fd <= 0 {
            return;
        }
        let pid = id >> 32;
        let conn_id_p = ConnId{
            pid: pid as u32,
            fd: ret_fd,
            creation_time: bpf_ktime_get_ns()
        };

        let conn_info = ConnInfo {
            conn_id: conn_id_p,
            wr_bytes: 0,
            rd_bytes: 0,
            is_http: false
        };

        let pid_fd = gen_tgid_fd(pid as u32, ret_fd);

        let res = CONN_INFO_MAP.insert(&pid_fd, &conn_info, 0);
        if res.is_err() {
            error!(ctx, "Failed to insert connection info");
        }

        let open_event = SocketOpenEvent {
            timestamp_ns: bpf_ktime_get_ns(),
            conn_id: conn_id_p,
            addr: args.addr
        };
        SOCKET_OPEN_EVENTS.output(ctx, &open_event, 0);

        }
}

fn process_syscall_close(ctx: &TracePointContext, id: u64, args: &CloseArgs) {
    unsafe {
        let ret_val = bpf_get_retval();
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
            rd_bytes: conn_info.rd_bytes
        };

        SOCKET_CLOSE_EVENTS.output(ctx, &close_event, 0);
        CONN_INFO_MAP.remove(&tgid_fd).unwrap()
    }
}

fn process_data(ctx: &TracePointContext, id: u64, direction: TrafficDirection, args: &DataArgs, bytes_count: isize) {
    if args.buf.is_null() {
        return;
    }

    if bytes_count <= 0 {
        return;
    }

    unsafe {
        let pid = (id >> 32) as u32;
        let pid_fd = gen_tgid_fd(pid, args.fd);
        let conn_info_ptr = match CONN_INFO_MAP.get_ptr_mut(&pid_fd) {
            Some(conn_info_ptr) => conn_info_ptr,
            None => return
        };
        let conn_info = &mut *conn_info_ptr;

        //convert pointer to buffer
        let buf = from_raw_parts(args.buf, bytes_count as usize).as_bytes();

        if is_http_connection(conn_info, buf) {
            let k_zero: u32 = 0;

            let event_ptr = SOCKET_DATA_EVENT_BUFFER_HEAP.get_ptr_mut(k_zero).unwrap();
            if event_ptr.is_null() {
                error!(ctx, "Failed to get mutable event buffer");
                return;
            }
            let event = unsafe { &mut *event_ptr };

            // Fill the metadata of the data event.
            event.attributes.timestamp = bpf_ktime_get_ns();
            event.attributes.traffic_direction = direction;
            event.attributes.conn_id = conn_info.conn_id;

            perf_submit_wrapper(ctx, direction, buf, bytes_count as usize, conn_info, event);
        }
        match direction {
            TrafficDirection::OUT => conn_info.wr_bytes += bytes_count as u64,
            TrafficDirection::IN => conn_info.rd_bytes += bytes_count as u64,
        }
        // Update the connection info
        let res = CONN_INFO_MAP.insert(&pid_fd, &conn_info, 0);
        if res.is_err() {
            error!(ctx, "Failed to update connection info");
        }
    }

}