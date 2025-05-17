---
layout: default
title: Metrics Collector API
---

# Metrics Collector API Reference

The `MetricsCollector` class handles the collection and reporting of metrics related to WAFIShield's operation.

## Initialization

```python
from wafishield.metrics import MetricsCollector

metrics = MetricsCollector()
```

## Methods

### increment()

Increment a metric counter.

```python
metrics.increment(metric_name, value=1)
```

**Parameters:**
- `metric_name` (str): Name of the metric to increment
- `value` (int/float, optional): Value to increment by (default: 1)

### get_current_metrics()

Get all current metrics as a dictionary.

```python
current_metrics = metrics.get_current_metrics()
```

**Returns:**
- Dictionary containing all collected metrics

### register_telemetry_handler()

Register a custom handler for forwarding metrics to external systems.

```python
metrics.register_telemetry_handler(handler_function)
```

**Parameters:**
- `handler_function` (callable): Function to call with metrics

### setup_opentelemetry()

Configure OpenTelemetry integration.

```python
metrics.setup_opentelemetry(
    service_name="wafishield-service",
    endpoint="http://otel-collector:4317"
)
```

**Parameters:**
- `service_name` (str): Name of the service
- `endpoint` (str): OpenTelemetry collector endpoint
- `additional_config` (dict, optional): Additional configuration options

## Default Metrics

WAFIShield tracks the following metrics by default:

### Request/Response Metrics

- `prompts_total`: Total number of prompts evaluated
- `responses_total`: Total number of responses evaluated

### Result Metrics

- `rules_failed`: Number of evaluations that failed rule checks
- `sanitizations_applied`: Number of evaluations where sanitization was applied
- `llm_checks`: Number of evaluations sent to the secondary LLM
- `llm_checks_failed`: Number of evaluations that failed LLM checks
- `llm_checks_skipped_after_sanitization`: Number of times LLM evaluation was skipped after sanitization

### Detailed Metrics

- `rule_{rule_id}_failed`: Count of failures for specific rules
- `sanitizer_{pattern_id}_applied`: Count of specific patterns applied

### System Metrics

- `started_at`: UNIX timestamp when metrics collection started
- `uptime_seconds`: Time since metrics collection started

## OpenTelemetry Integration

WAFIShield supports sending metrics to OpenTelemetry for integration with observability platforms:

```python
# Configure OpenTelemetry
wafishield.metrics.setup_opentelemetry(
    service_name="my-llm-service",
    endpoint="http://otel-collector:4317"
)
```

## Custom Telemetry Handlers

You can also register custom handlers to send metrics to any system:

```python
def statsd_handler(metric_name, value):
    # Send to StatsD
    statsd.gauge(f"wafishield.{metric_name}", value)

def prometheus_handler(metric_name, value):
    # Update Prometheus metric
    if metric_name in prometheus_metrics:
        prometheus_metrics[metric_name].set(value)

# Register handlers
wafishield.metrics.register_telemetry_handler(statsd_handler)
wafishield.metrics.register_telemetry_handler(prometheus_handler)
```
