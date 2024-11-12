use std::{mem::MaybeUninit, path::PathBuf, time::Duration};

use clap::Parser;
use eyre::{Result, WrapErr};
use hashbrown::HashMap;
use hdrhistogram::Histogram;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, RingBufferBuilder,
};
use plain::Plain;
use tracing::{debug, error, level_filters::LevelFilter, warn};
use tracing_subscriber::EnvFilter;

mod perfspan {
    include!(concat!(env!("OUT_DIR"), "/perfspan.skel.rs"));
}

unsafe impl Plain for perfspan::types::event {}

type Event = perfspan::types::event;

#[derive(Parser)]
struct Opt {
    #[clap(short, long, help = "path to the binary to monitor")]
    binary: PathBuf,
    #[clap(
        short,
        long,
        help = "pid of the process to monitor. optional, if not provided all spans will be collected"
    )]
    pid: Option<i32>,
    #[clap(required = true, help = "list of spans to monitor")]
    spans: Vec<String>,
}

const USDT_PROVIDER: &str = "perfspan";
const USDT_ENTER: &str = "enter";
const USDT_EXIT: &str = "exit";

fn main() -> Result<()> {
    // this is set so that ring.poll doesn't exit without handing out control back to the main
    ctrlc::set_handler(|| {
        debug!("received interrupt, exiting");
    })
    .wrap_err("failed to set interrupt handler")?;

    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let opt = Opt::parse();

    let mut links = vec![];
    let mut open_object = MaybeUninit::uninit();
    let builder = perfspan::PerfspanSkelBuilder::default()
        .open(&mut open_object)
        .wrap_err("failed to open BPF object")?;
    let skel = builder.load()?;

    links.push(skel.progs.perfspan_enter.attach_usdt(
        -1,
        &opt.binary,
        USDT_PROVIDER,
        USDT_ENTER,
    )?);
    links.push(
        skel.progs
            .perfspan_exit
            .attach_usdt(-1, &opt.binary, USDT_PROVIDER, USDT_EXIT)?,
    );

    for (i, span) in opt.spans.iter().enumerate() {
        let name = null_terminated_string(span);
        debug!("inserting span name: {:?} with index {}", name, i);
        skel.maps
            .filter_by_name
            .update(&name, &(i as u8).to_ne_bytes(), MapFlags::ANY)
            .wrap_err("failed to insert span name")?;
    }
    let mut hist_per_span: Vec<Histogram<u64>> = opt
        .spans
        .iter()
        .map(|_| Histogram::new_with_bounds(1_000, 1_000_000_000, 3).expect("messed up arguments"))
        .collect::<Vec<_>>();
    {
        let mut open_spans = HashMap::new();
        let mut ring = RingBufferBuilder::new();
        ring.add(&skel.maps.events, |buf| {
            let ev = match plain::from_bytes::<Event>(buf) {
                Ok(ev) => ev,
                Err(e) => {
                    error!("failed to parse event: {:?}", e);
                    return 1;
                }
            };
            match ev.r#type {
                0 => {
                    open_spans.insert((ev.pid_tgid, ev.span_id), *ev);
                }
                1 => match open_spans.remove(&(ev.pid_tgid, ev.span_id)) {
                    Some(previous) => {
                        hist_per_span[previous.name_id as usize]
                            .saturating_record(ev.timestamp - previous.timestamp);
                    }
                    None => {
                        warn!(
                            "missed opening event for span {}/{}",
                            ev.pid_tgid, ev.span_id
                        );
                    }
                },
                _ => {
                    error!("unknown event type: {}", ev.r#type);
                    return 1;
                }
            }
            0
        })?;
        let ring = ring.build()?;
        loop {
            match ring.poll(Duration::MAX) {
                Ok(_) => {}
                Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {
                    break;
                }
                Err(e) => {
                    error!("error polling ring buffer: {:?}", e);
                    eyre::bail!("error polling ring buffer: {:?}", e);
                }
            }
        }
    }
    hist_per_span
        .into_iter()
        .zip(opt.spans.iter())
        .for_each(|(hist, span)| {
            println!(
                "\n{}: samples {} min {} max {} mean {:.2} stdev {:.2} p90 {} p99 {}",
                span,
                hist.len(),
                hist.min(),
                hist.max(),
                hist.mean(),
                hist.stdev(),
                hist.value_at_quantile(0.9),
                hist.value_at_quantile(0.99)
            );
            if hist.is_empty() {
                return;
            }
            hist.iter_log(hist.min(), 2.0)
                .skip_while(|v| v.quantile() < 0.01)
                .for_each(|v| {
                    println!(
                        "{:4}µs | {:40} | {:4.1}th %-ile",
                        (v.value_iterated_to() + 1) / 1_000,
                        "*".repeat(
                            (v.count_since_last_iteration() as f64 * 40.0 / hist.len() as f64)
                                .ceil() as usize
                        ),
                        v.percentile(),
                    );
                });
            println!();
        });
    Ok(())
}

// this value should be consistent with value set in perfspan.h
const MAX_NAME_SIZE: usize = 128;

fn null_terminated_string(s: &str) -> [u8; MAX_NAME_SIZE] {
    let mut buf = [0; MAX_NAME_SIZE];
    let bytes = s.as_bytes();
    buf[..bytes.len()].copy_from_slice(bytes);
    buf
}
