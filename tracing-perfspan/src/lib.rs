use probe::probe;
use tracing::{level_filters::LevelFilter, span, Subscriber};
use tracing_subscriber::{
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
    Layer,
};

/// Initialize tracing with PerfspanLayer.
///
/// Uses DEBUG as the default level for spans, but can be overridden by setting
/// the PERF_SPAN_LEVEL environment variable.
pub fn init() {
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .with_env_var("PERF_SPAN_LEVEL")
        .from_env_lossy();
    let layer = PerfspanLayer {}.with_filter(env_filter);
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

pub struct PerfspanLayer {}

impl<S> Layer<S> for PerfspanLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let name_size = span.name().len() as u16;
            let name = span.name().as_ptr();
            let span_id = span.id().into_u64();
            probe!(perfspan, enter, span_id, name_size, name);
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let name_size = span.name().len() as u16;
            let name = span.name().as_ptr();
            let span_id = span.id().into_u64();
            probe!(perfspan, exit, span_id, name_size, name);
        }
    }
}
