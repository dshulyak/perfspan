use std::{thread::sleep, time::Duration};

use perfspan::PerfspanSubscriber;
use tracing::{instrument, level_filters::LevelFilter};
use tracing_subscriber::{prelude::*, Registry};

fn main() {
    let registry = Registry::default().with(
        PerfspanSubscriber {}.with_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        ),
    );
    tracing::dispatcher::set_global_default(registry.into())
        .expect("failed to set global default subscriber");

    loop {
        anything();
    }
}

#[instrument]
fn anything() {
    sleep(Duration::from_secs(1));
}
