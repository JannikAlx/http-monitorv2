#![feature(str_from_raw_parts)]
#![no_std]
#![no_main]

mod maps_http;
mod helper_http;

use core::ptr::{null, write};
use http_monitor_common::{DataArgs, sockaddr_in};

use core::str::from_utf8_unchecked;
use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_ebpf::bindings::sockaddr;
use aya_ebpf::helpers;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};
use aya_ebpf::macros::{btf_tracepoint, map, raw_tracepoint};
use aya_log_ebpf::{error, info};
use aya_ebpf::maps::ring_buf::RingBuf;
use aya_ebpf::programs::{BtfTracePointContext, RawTracePointContext};
use http_monitor_common::AcceptArgs;
use http_monitor_common::TrafficDirection::OUT;
use crate::helper_http::{process_data, process_syscall_accept};
use crate::maps_http::{ACTIVE_ACCEPT_ARGS_MAP, ACTIVE_WRITE_ARGS_MAP};
//MAPS

#[map]
static mut RING_BUF1: RingBuf = RingBuf::with_byte_size(1028, 0);

#[tracepoint]
pub fn http_monitor(ctx: TracePointContext) -> u32 {
    match try_http_monitor(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_http_monitor(ctx: TracePointContext) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().unwrap();
    let curl_name = "curl".as_bytes();
    unsafe {
        let comm_string = from_utf8_unchecked(&comm);
        info!(&ctx, "Comm: {}", comm_string);
        if !comm_string.contains("systemd") {
            if RING_BUF1.output(&comm_string,0).is_ok() {
                info!(&ctx, "Saved item to RingBuffer")
            }

        }
    }
    Ok(0)
}

#[tracepoint]
fn syscall_probe_entry_accept(ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    unsafe {
        let addr :sockaddr = ctx.read_at(24).unwrap();

        let accept_args: AcceptArgs = AcceptArgs {
            addr
        };
        ACTIVE_ACCEPT_ARGS_MAP.insert(&id, &accept_args, 0).map_err(|e| e as u8).unwrap();
    };
    0
}

#[tracepoint]
fn syscall_probe_entry_accept4(ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    unsafe {
        let addr :sockaddr = ctx.read_at(24).unwrap();

        let accept_args: AcceptArgs = AcceptArgs {
            addr
        };
        ACTIVE_ACCEPT_ARGS_MAP.insert(&id, &accept_args, 0).map_err(|e| e as u8).unwrap();
    };
    0
}

#[tracepoint]
fn syscall_probe_ret_accept(ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    unsafe {
        let accept_args = ACTIVE_ACCEPT_ARGS_MAP.get(&id);
        if accept_args.is_some() {
            let args = accept_args.unwrap();
            process_syscall_accept(&ctx, id, args)
        }
        if ACTIVE_ACCEPT_ARGS_MAP.remove(&id).is_err() {
            error! {&ctx, "Failed to remove accept args from map"}
        }
    }
    0
}

#[tracepoint]
fn syscall_probe_ret_accept4(ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    unsafe {
        let accept_args = ACTIVE_ACCEPT_ARGS_MAP.get(&id);
        if accept_args.is_some() {
            let args = accept_args.unwrap();
            process_syscall_accept(&ctx, id, args)
        }
        if ACTIVE_ACCEPT_ARGS_MAP.remove(&id).is_err() {
            error! {&ctx, "Failed to remove accept args from map"}
        }
    }
    0
}

// original signature: ssize_t write(int fd, const void *buf, size_t count);
#[tracepoint]
fn syscall_probe_entry_write(ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    unsafe {
        let fd: i32 = ctx.read_at(16).unwrap_or_default();
        //makes verifier mad if not default
        let buf: *const u8 = ctx.read_at(24).unwrap_or(null::<u8>());

        let write_args = DataArgs {
            fd,
            buf,
        };
        ACTIVE_WRITE_ARGS_MAP.insert(&id, &write_args, 0).map_err(|e| e as u8).unwrap();
    };
    0
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
