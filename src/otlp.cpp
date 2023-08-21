#include "otlp.h"


namespace trace = opentelemetry::trace;
namespace nostd = opentelemetry::nostd;

nostd::shared_ptr<trace::Tracer> get_tracer()
{
    auto provider = trace::Provider::GetTracerProvider();
    return provider->GetTracer("zero tracer data source", OPENTELEMETRY_SDK_VERSION);
}

namespace trace = opentelemetry::trace;
namespace trace_sdk = opentelemetry::sdk::trace;
namespace otlp = opentelemetry::exporter::otlp;

namespace internal_log = opentelemetry::sdk::common::internal_log;


opentelemetry::exporter::otlp::OtlpHttpExporterOptions opts;
void InitTracer()
{
    // Create OTLP exporter instance
    auto exporter = otlp::OtlpHttpExporterFactory::Create(opts);
    auto processor = trace_sdk::SimpleSpanProcessorFactory::Create(std::move(exporter));


    std::shared_ptr<opentelemetry::trace::TracerProvider> provider =
        trace_sdk::TracerProviderFactory::Create(std::move(processor));
    // Set the global trace provider
    trace::Provider::SetTracerProvider(provider);
}

void CleanupTracer()
{
    // We call ForceFlush to prevent to cancel running exportings, It's optional.
    opentelemetry::nostd::shared_ptr<opentelemetry::trace::TracerProvider> provider =
        trace::Provider::GetTracerProvider();
    if (provider)
    {
        static_cast<trace_sdk::TracerProvider *>(provider.get())->ForceFlush();
    }

    std::shared_ptr<opentelemetry::trace::TracerProvider> none;
    trace::Provider::SetTracerProvider(none);
}