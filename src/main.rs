use std::{mem::MaybeUninit, path::PathBuf, time::Duration};

use clap::Parser;
use eyre::{Result, WrapErr};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

mod stacks {
    include!(concat!(env!("OUT_DIR"), "/perfspan.skel.rs"));
}

#[derive(Parser)]
struct Opt {
    #[clap(short, long, help = "path to the binary to monitor")]
    binary: PathBuf,
    #[clap(short, long, help = "pid of the process to monitor")]
    pid: i32,
    #[clap(short, long, help = "list of spans to monitor")]
    spans: Vec<String>,
}

const USDT_PROVIDER: &str = "perfspan";
const USDT_ENTER: &str = "enter";
const USDT_EXIT: &str = "exit";

fn main() -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let opt = Opt::parse();

    let mut links = vec![];
    let mut open_object = MaybeUninit::uninit();
    let builder = stacks::PerfspanSkelBuilder::default()
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
    let mut ring = RingBufferBuilder::new();

    ring.add(&skel.maps.events, |buf| {
        info!("length {} event: {:?}", buf.len(), buf);
        0
    })?;
    let ring = ring.build()?;
    loop {
        ring.poll(Duration::MAX)?;
    }
    Ok(())
}
