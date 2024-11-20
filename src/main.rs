use std::{mem::MaybeUninit, path::PathBuf, str::FromStr, time::Duration};

use clap::Parser;
use eyre::{Result, WrapErr};
use hashbrown::HashMap;
use hdrhistogram::{iterators::IterationValue, Histogram};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, OpenObject, RingBufferBuilder,
};
use perf::{
    attach_event_with_cookie, enable_on_all_cpus, open_cycles_event, open_instructions_event,
};
use perfspan::PerfspanSkel;
use plain::Plain;
use tracing::{debug, error, level_filters::LevelFilter, trace, warn};
use tracing_subscriber::EnvFilter;

mod perfspan {
    include!(concat!(env!("OUT_DIR"), "/perfspan.skel.rs"));
}
mod perf;

unsafe impl Plain for perfspan::types::event {}

type Event = perfspan::types::event;

#[derive(Parser)]
struct Opt {
    #[clap(help = "path to the binary to monitor", required = true)]
    binary: PathBuf,
    #[clap(help = "list of spans to monitor", required = true)]
    spans: Vec<String>,
    #[clap(
        short,
        long,
        help = "pid of the process to monitor. optional, if not provided spans from all processes will be collected"
    )]
    pid: Option<i32>,
    #[clap(
        short,
        long,
        help = "collect additional performance events for each span. 
        examples: 
            - cycles
        Ccollect cycles event with default sample_period=10_000_000
            - instructions=1000000
        Collect instructions event with sample_period=1_000_000
            - cache_ref=2=10000
        Collect cache references event with config=2 and sample_period=10_000
        The name (first part) is only for UX purposes, the actual captured event is determined by the config"
    )]
    events: Vec<PerfEvent>,
    #[clap(
        short,
        long,
        help = "number of buckets for the histogram",
        default_value = "10"
    )]
    buckets: u64,
}

const USDT_PROVIDER: &str = "perfspan";
const USDT_ENTER: &str = "enter";
const USDT_EXIT: &str = "exit";

const DEFAULT_SAMPLE_PERIOD: u64 = 10_000_000;

const CYCLES: &str = "cycles";
const INSTRUCTIONS: &str = "instructions";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PerfEvent {
    Cycles(u64),
    Instructions(u64),
    Custom(String, u64, u64),
}

impl PerfEvent {
    fn as_str(&self) -> &str {
        match self {
            Self::Cycles(_) => CYCLES,
            Self::Instructions(_) => INSTRUCTIONS,
            Self::Custom(name, _, _) => name,
        }
    }

    fn enable(&self, pid: i32, cpu: i32) -> Result<i64> {
        match self {
            Self::Cycles(period) => open_cycles_event(pid, cpu, *period),
            Self::Instructions(period) => open_instructions_event(pid, cpu, *period),
            Self::Custom(_, config, period) => {
                perf::open_hardware_event(pid, cpu, *config, *period)
            }
        }
    }
}

impl FromStr for PerfEvent {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split("=");

        let event = parts
            .next()
            .ok_or_else(|| eyre::eyre!("missing event type"))?;

        let parse_period = |period: Option<&str>| -> Result<u64> {
            let period = period.map_or(Ok(DEFAULT_SAMPLE_PERIOD), |p| {
                p.parse()
                    .wrap_err_with(|| format!("failed to parse sample_period: {}", p))
            })?;
            Ok(period)
        };

        match event {
            CYCLES => Ok(Self::Cycles(parse_period(parts.next())?)),
            INSTRUCTIONS => Ok(Self::Instructions(parse_period(parts.next())?)),
            _ => {
                let config = parts
                    .next()
                    .ok_or_else(|| eyre::eyre!("missing config"))?
                    .parse()?;
                let period = parse_period(parts.next())?;
                Ok(Self::Custom(event.to_string(), config, period))
            }
        }
    }
}

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

    let counters_max_size = Event::default().counters.len();
    eyre::ensure!(
        opt.events.len() <= counters_max_size,
        "too many events requested, max is {}",
        counters_max_size
    );

    let mut open_object = MaybeUninit::uninit();
    let (skel, _links) = register_bpf_program(&opt, &mut open_object)?;

    let mut histograms_perf_span: Vec<SpanHistograms> = opt
        .spans
        .iter()
        .map(|span| SpanHistograms::new(span.clone(), opt.events.iter().cloned()))
        .collect::<Vec<_>>();
    poll_events(skel, &mut histograms_perf_span)?;

    println!(); // separate ^C from the output
    for hist in histograms_perf_span.iter() {
        hist.print(opt.buckets);
    }
    Ok(())
}

fn register_bpf_program<'b>(
    opt: &Opt,
    open_object: &'b mut MaybeUninit<OpenObject>,
) -> Result<(PerfspanSkel<'b>, Vec<Link>)> {
    let mut links = vec![];
    let builder = perfspan::PerfspanSkelBuilder::default()
        .open(open_object)
        .wrap_err("failed to open BPF object")?;
    builder.maps.rodata_data.cfg.filter_tgid = opt.pid.unwrap_or(0) as u32;
    builder.maps.rodata_data.cfg.enabled_events = opt.events.len() as u32;
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
    for (cookie, event) in opt.events.iter().enumerate() {
        let pfds = enable_on_all_cpus(|cpu| event.enable(opt.pid.unwrap_or(-1), cpu))?;
        for pfd in pfds.iter() {
            debug!("opened perf event: {}", pfd);
            let link =
                attach_event_with_cookie(&skel.progs.on_perf_event, *pfd as i32, cookie as u64)?;
            links.push(link);
        }
    }
    for (i, span) in opt.spans.iter().enumerate() {
        let name = max_name_size_string(span);
        debug!("watching span name: {} with index {}", span, i);
        skel.maps
            .filter_by_name
            .update(&name, &(i as u8).to_ne_bytes(), MapFlags::ANY)
            .wrap_err("failed to insert span name")?;
    }
    Ok((skel, links))
}

fn poll_events(skel: PerfspanSkel<'_>, histograms_per_span: &mut [SpanHistograms]) -> Result<()> {
    let mut open_spans = HashMap::new();
    let mut ring = RingBufferBuilder::new();
    ring.add(&skel.maps.events, |buf| {
        trace!("received event {:?}", buf);
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
                    debug!(
                        "closing span {}/{} with latency {}. counters {:?} {:?}",
                        ev.pid_tgid,
                        ev.span_id,
                        ev.timestamp - previous.timestamp,
                        ev.counters,
                        previous.counters
                    );
                    histograms_per_span[ev.name_id as usize].record_event(ev, &previous);
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
                return Ok(());
            }
            Err(e) => {
                error!("error polling ring buffer: {:?}", e);
                eyre::bail!("error polling ring buffer: {:?}", e);
            }
        }
    }
}

// this value should be consistent with value set in perfspan.h
const MAX_NAME_SIZE: usize = 128;

fn max_name_size_string(s: &str) -> [u8; MAX_NAME_SIZE] {
    let mut buf = [0; MAX_NAME_SIZE];
    let bytes = s.as_bytes();
    buf[..bytes.len()].copy_from_slice(bytes);
    buf
}

struct SpanHistograms {
    span_name: String,
    latency: Histogram<u64>,
    counters: Vec<(PerfEvent, Histogram<u64>)>,
}

impl SpanHistograms {
    fn new(span_name: String, perf_events: impl Iterator<Item = PerfEvent>) -> Self {
        let latency = Histogram::new_with_bounds(1, u64::MAX, 3).expect("messed up arguments");
        let counters = perf_events
            .map(|event| {
                (
                    event,
                    Histogram::new_with_bounds(1, u64::MAX, 3).expect("messed up arguments"),
                )
            })
            .collect::<Vec<_>>();
        Self {
            span_name,
            latency,
            counters,
        }
    }

    fn record_event(&mut self, current: &Event, previous: &Event) {
        self.latency
            .saturating_record(current.timestamp - previous.timestamp);
        for (event, (_, hist)) in self.counters.iter_mut().enumerate() {
            if current.cpu != previous.cpu {
                warn!(
                    "event migrated cpu from {} to {}",
                    previous.cpu, current.cpu
                );
                continue;
            }
            if current.counters[event] < previous.counters[event] {
                warn!(
                    "counter {} decreased from {} to {}",
                    event, previous.counters[event], current.counters[event]
                );
                continue;
            }
            hist.saturating_record(current.counters[event] - previous.counters[event]);
        }
    }

    fn print(&self, buckets: u64) {
        println!("SPAN: {}", self.span_name);
        print_histogram(
            &self.span_name,
            "latency",
            buckets,
            &self.latency,
            print_latency_distribution,
        );
        for (event, hist) in self.counters.iter() {
            print_histogram(
                &self.span_name,
                event.as_str(),
                buckets,
                hist,
                print_counters_distribution,
            );
        }
    }
}

fn print_histogram(
    span: &str,
    kind: &str,
    buckets: u64,
    hist: &Histogram<u64>,
    print_fn: impl Fn(IterationValue<u64>, u64),
) {
    println!(
        "{} {}: samples {} min {} max {} mean {:.2} stdev {:.2} p80 {} p95 {}",
        span,
        kind,
        hist.len(),
        hist.min(),
        hist.max(),
        hist.mean(),
        hist.stdev(),
        hist.value_at_quantile(0.8),
        hist.value_at_quantile(0.95)
    );
    if hist.is_empty() {
        return;
    }
    let print_fn = |v| print_fn(v, hist.len());
    hist.iter_linear(((hist.max() - hist.min()) as f64 / buckets as f64).ceil() as u64)
        .skip_while(|v| v.quantile() < 0.01)
        .for_each(print_fn);
}

fn print_latency_distribution(v: IterationValue<u64>, total_count: u64) {
    println!(
        "{:4}µs | {:40} | {:4.1}th %-ile",
        (v.value_iterated_to() + 1) / 1_000,
        "*".repeat(
            (v.count_since_last_iteration() as f64 * 50.0 / total_count as f64).ceil() as usize
        ),
        v.percentile(),
    );
}

fn print_counters_distribution(v: IterationValue<u64>, total_count: u64) {
    println!(
        "{:10} | {:40} | {:4.1}th %-ile",
        v.value_iterated_to(),
        "*".repeat(
            (v.count_since_last_iteration() as f64 * 50.0 / total_count as f64).ceil() as usize
        ),
        v.percentile(),
    );
}
