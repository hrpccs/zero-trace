// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "opentelemetry/exporters/otlp/otlp_http_exporter_factory.h"
#include "opentelemetry/exporters/otlp/otlp_http_exporter_options.h"
#include "opentelemetry/sdk/common/global_log_handler.h"
#include "opentelemetry/sdk/trace/processor.h"
#include "opentelemetry/sdk/trace/simple_processor_factory.h"
#include "opentelemetry/sdk/trace/tracer_provider_factory.h"
#include "opentelemetry/trace/provider.h"

// sdk::TracerProvider is just used to call ForceFlush and prevent to cancel running exportings when
// destroy and shutdown exporters.It's optional to users.
#include "opentelemetry/sdk/trace/tracer_provider.h"

#include <string>

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "opentelemetry/sdk/version/version.h"
#include "opentelemetry/trace/provider.h"

#include <iostream>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include "message.pb.h"
#include <unistd.h>
#include <arpa/inet.h>
namespace trace = opentelemetry::trace;
namespace nostd = opentelemetry::nostd;

nostd::shared_ptr<trace::Tracer> get_tracer()
{
    auto provider = trace::Provider::GetTracerProvider();
    return provider->GetTracer("foo_library", OPENTELEMETRY_SDK_VERSION);
}

opentelemetry::v1::trace::EndSpanOptions CreateEndSpanOpt(int duration)
{
    auto span = get_tracer()->StartSpan("some span");
    opentelemetry::v1::common::SteadyTimestamp t1{std::chrono::steady_clock::now() + std::chrono::microseconds{duration}};
    opentelemetry::v1::trace::EndSpanOptions end_opt;
    end_opt.end_steady_time = t1;
    return end_opt;
}

void emitRequestOtlp(ProtoRequest &req)
{
    auto rootSpan = get_tracer()->StartSpan("request"); // 后面再添加
    auto rootScope = get_tracer()->WithActiveSpan(rootSpan);

    int req_events_size = req.proto_events_size();
    std::cout << "span events num = " << req_events_size << std::endl;
    for (int i = 0; i < req_events_size; ++i)
    {
        const ProtoEvent &event = req.proto_events(i);
        if (event.proto_trigger_type() == ProtoTriggerType::proto_trigger_entry)
        {
            auto tmpSpan = get_tracer()->StartSpan(std::to_string(event.proto_event_id()));
            auto tmpScope = get_tracer()->WithActiveSpan(tmpSpan);
        }
        else if (event.proto_trigger_type() == ProtoTriggerType::proto_trigger_exit)
        {
            get_tracer()->GetCurrentSpan()->End(CreateEndSpanOpt(event.proto_event_duration()));
        }
        else
        {
            auto tmpSpan = get_tracer()->StartSpan(std::to_string(event.proto_event_id()));
            auto tmpScope = get_tracer()->WithActiveSpan(tmpSpan);
            tmpSpan->End(CreateEndSpanOpt(event.proto_event_duration()));
        }
    }

    rootSpan->End(CreateEndSpanOpt(req.proto_request_duration()));
}

int server()
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[1024];

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Error creating socket");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(12345);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error binding socket");
        close(sockfd);
        return -1;
    }

    std::cout << "Server listening on port 12345..." << std::endl;
    int count = 0;
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);

        if (bytes_received < 0)
        {
            perror("Error receiving data");
            continue;
        }

        ProtoRequest request;
        if (request.ParseFromArray(buffer, bytes_received))
        {

            //std::cout << "Request duration = " << request.proto_request_duration() << std::endl;

            emitRequestOtlp(request);
        }
    }

    close(sockfd);
    return 0;
}

namespace trace = opentelemetry::trace;
namespace trace_sdk = opentelemetry::sdk::trace;
namespace otlp = opentelemetry::exporter::otlp;

namespace internal_log = opentelemetry::sdk::common::internal_log;

namespace
{
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
} // namespace

/*
  Usage:
  - example_otlp_http
  - example_otlp_http <URL>
  - example_otlp_http <URL> <DEBUG>
  - example_otlp_http <URL> <DEBUG> <BIN>
  <DEBUG> = yes|no, to turn console debug on or off
  <BIN> = bin, to export in binary format
*/
int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        opts.url = argv[1];
        if (argc > 2)
        {
            std::string debug = argv[2];
            opts.console_debug = debug != "" && debug != "0" && debug != "no";
        }

        if (argc > 3)
        {
            std::string binary_mode = argv[3];
            if (binary_mode.size() >= 3 && binary_mode.substr(0, 3) == "bin")
            {
                opts.content_type = otlp::HttpRequestContentType::kBinary;
            }
        }
    }

    if (opts.console_debug)
    {
        internal_log::GlobalLogHandler::SetLogLevel(internal_log::LogLevel::Debug);
    }

    // Removing this line will leave the default noop TracerProvider in place.
    InitTracer();

    int suc = server();

    CleanupTracer();
}
