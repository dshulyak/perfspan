use probe::probe;
use tracing::{span, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

pub struct PerfspanSubscriber {}

impl<S> Layer<S> for PerfspanSubscriber
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let name_size = span.name().len();
            let name = span.name().as_ptr();
            let span_id = span.id().into_u64();
            probe!(perfspan, enter, span_id, name_size, name);
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let span_id = span.id().into_u64();
            probe!(perfspan, exit, span_id);
        }
    }
}
