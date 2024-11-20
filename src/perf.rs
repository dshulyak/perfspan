use std::{io, mem, ptr::NonNull};

use eyre::{Result, WrapErr};
use libbpf_rs::{
    libbpf_sys::{
        bpf_perf_event_opts, bpf_program__attach_perf_event_opts, libbpf_get_error,
        perf_event_attr, PERF_COUNT_HW_CPU_CYCLES, PERF_COUNT_HW_INSTRUCTIONS, PERF_SAMPLE_RAW,
        PERF_TYPE_HARDWARE,
    },
    AsRawLibbpf, Error as BPFError, Link, ProgramMut,
};
use libc::{self, SYS_perf_event_open};

pub fn enable_on_all_cpus<F: Fn(i32) -> Result<i64>>(open_event_fn: F) -> Result<Vec<i64>> {
    let mut fds = Vec::new();
    for cpu in 0..libbpf_rs::num_possible_cpus()? {
        let fd = open_event_fn(cpu as i32)?;
        fds.push(fd);
    }
    Ok(fds)
}

pub fn open_cycles_event(pid: i32, cpu: i32, period: u64) -> Result<i64> {
    open_hardware_event(pid, cpu, PERF_COUNT_HW_CPU_CYCLES as u64, period)
}

pub fn open_instructions_event(pid: i32, cpu: i32, period: u64) -> Result<i64> {
    open_hardware_event(pid, cpu, PERF_COUNT_HW_INSTRUCTIONS as u64, period)
}

pub fn open_hardware_event(pid: i32, cpu: i32, config: u64, period: u64) -> Result<i64> {
    open_event(PERF_TYPE_HARDWARE, PERF_SAMPLE_RAW as u64, config, period, pid, cpu, 0)
}

pub fn attach_event_with_cookie(prog: &ProgramMut<'_>, pfd: i32, cookie: u64) -> Result<Link> {
    let opts = bpf_perf_event_opts {
        sz: mem::size_of::<bpf_perf_event_opts>() as u64,
        bpf_cookie: cookie,
        ..Default::default()
    };
    let ret = unsafe {
        bpf_program__attach_perf_event_opts(prog.as_libbpf_object().as_ptr(), pfd, &opts)
    };
    let ptr = validate_bpf_ret(ret).wrap_err("failed to attach perf event")?;
    // SAFETY: the pointer came from libbpf and has been checked for errors.
    let link = unsafe { Link::from_ptr(ptr) };
    Ok(link)
}

fn open_event(
    type_: u32,
    sample_type: u64,
    config: u64,
    period: u64,
    pid: i32,
    cpu: i32,
    flags: u32,
) -> Result<i64> {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.config = config;
    attr.type_ = type_;
    attr.sample_type = sample_type;
    attr.set_inherit(0);
    attr.__bindgen_anon_2.wakeup_events = 0;

    attr.__bindgen_anon_1.sample_period = period;

    let rst = unsafe { libc::syscall(SYS_perf_event_open, &attr, pid, cpu, -1, flags) };
    match rst {
        fd @ 0.. => Ok(fd),
        _ => eyre::bail!("io error {}/{}:", rst, io::Error::last_os_error()),
    }
}

// copied from libbpf-rs as the util module is not public
/// Check the returned pointer of a `libbpf` call, extracting any
/// reported errors and converting them.
pub fn validate_bpf_ret<T>(ptr: *mut T) -> Result<NonNull<T>> {
    // SAFETY: `libbpf_get_error` is always safe to call.
    match unsafe { libbpf_get_error(ptr as *const _) } {
        0 => {
            debug_assert!(!ptr.is_null());
            // SAFETY: libbpf guarantees that if NULL is returned an
            //         error it set, so we will always end up with a
            //         valid pointer when `libbpf_get_error` returned 0.
            let ptr = unsafe { NonNull::new_unchecked(ptr) };
            Ok(ptr)
        }
        err => Err(BPFError::from_raw_os_error(-err as i32).into()),
    }
}
