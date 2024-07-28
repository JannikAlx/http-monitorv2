use aya::programs::{RawTracePoint, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya::maps::{AsyncPerfEventArray, Map, MapData, PerfEventArray, RingBuf};
use aya_log::BpfLogger;
use log::{info, warn, debug, error};
use tokio::signal;
use tokio::time::{self, Duration};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard, AsyncFdReadyMutGuard};
use http_monitor_common::{DataOut, SocketDataEvent, SocketOpenEvent};
use std::convert::TryFrom;
use aya::util::online_cpus;
use bytes::BytesMut;


#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("error: {:#}", e);
    }
}

async fn try_main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/http-monitor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/http-monitor"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    load_programs(&mut bpf)?;


    // Process events from the perf buffer
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("SOCKET_OPEN_EVENTS").unwrap())?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {

                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SocketDataEvent;
                    let data = unsafe { ptr.read_unaligned() };
                    info!("Received event from pid: {}", data.attributes.conn_id.pid);
                }
            }
        });
    }

    signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c event");

    eprintln!("Exiting...");

    Ok(())
}

fn load_programs(bpf: &mut Bpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = bpf.program_mut("syscall_probe_entry_accept").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_accept")?;
    let program: &mut TracePoint = bpf.program_mut("syscall_probe_ret_accept").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_accept")?;
    let program: &mut TracePoint = bpf.program_mut("syscall_probe_entry_accept4").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_accept4")?;
    let program: &mut TracePoint = bpf.program_mut("syscall_probe_ret_accept4").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_accept4")?;
    let program: &mut TracePoint = bpf.program_mut("syscall_probe_entry_write").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_write")?;

    Ok(())
}