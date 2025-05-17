"""
Metrics collection and observability support.
"""

import time
import logging
from typing import Dict, Any, Optional


class MetricsCollector:
    """
    Metrics collector for WAFIShield.

    Collects and provides access to metrics related to:
    1. Rule evaluations (success/failures)
    2. Sanitizer applications
    3. LLM evaluations
    4. Overall package performance

    The metrics collector supports integration with OpenTelemetry and
    other observability tools.
    """

    def __init__(self):
        self.logger = logging.getLogger("wafishield.metrics")
        self.metrics = {
            "started_at": time.time(),
            "prompts_total": 0,
            "responses_total": 0,
            "rules_failed": 0,
            "sanitizations_applied": 0,
            "llm_checks": 0,
            "llm_checks_failed": 0,
            "rule_metrics": {},
            "pattern_metrics": {},
        }
        self._telemetry_handler = None

    def increment(self, metric_name: str, value: int = 1):
        """
        Increment a metric by the specified value.

        Args:
            metric_name: Name of the metric to increment
            value: Value to increment by (default is 1)
        """
        if metric_name in self.metrics:
            self.metrics[metric_name] += value
        elif metric_name.startswith("rule_") and "_failed" in metric_name:
            rule_id = metric_name.split("_failed")[0].replace("rule_", "")
            if rule_id not in self.metrics["rule_metrics"]:
                self.metrics["rule_metrics"][rule_id] = {"triggered": 0}
            self.metrics["rule_metrics"][rule_id]["triggered"] += value
        elif metric_name.startswith("sanitizer_") and "_applied" in metric_name:
            pattern_id = metric_name.split("_applied")[0].replace("sanitizer_", "")
            if pattern_id not in self.metrics["pattern_metrics"]:
                self.metrics["pattern_metrics"][pattern_id] = {"applied": 0}
            self.metrics["pattern_metrics"][pattern_id]["applied"] += value
        else:
            self.metrics[metric_name] = value

        # Forward metric to telemetry handler if configured
        if self._telemetry_handler:
            self._telemetry_handler(metric_name, value)

    def get_current_metrics(self) -> Dict[str, Any]:
        """
        Get the current metrics.

        Returns:
            Dictionary containing all current metrics
        """
        metrics_copy = self.metrics.copy()
        metrics_copy["uptime_seconds"] = time.time() - metrics_copy["started_at"]
        return metrics_copy

    def register_telemetry_handler(self, handler_func):
        """
        Register a function to handle metrics for external observability systems.

        The handler function should accept two parameters:
        - metric_name: Name of the metric
        - value: Value of the metric

        Args:
            handler_func: Function to call with metrics
        """
        self._telemetry_handler = handler_func
        self.logger.info("Registered telemetry handler")

    def setup_opentelemetry(
        self, service_name: str = "wafishield", endpoint: Optional[str] = None
    ):
        """
        Set up OpenTelemetry integration for metrics.

        Args:
            service_name: Name of the service for OpenTelemetry
            endpoint: Optional OpenTelemetry endpoint
        """
        try:
            # Import OpenTelemetry only when needed
            from opentelemetry import metrics
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import (
                ConsoleMetricExporter,
                PeriodicExportingMetricReader,
            )
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter,
            )

            # Create a meter provider with either console or OTLP exporter
            if endpoint:
                exporter = OTLPMetricExporter(endpoint=endpoint)
            else:
                exporter = ConsoleMetricExporter()

            reader = PeriodicExportingMetricReader(
                exporter, export_interval_millis=10000
            )
            provider = MeterProvider(metric_readers=[reader])

            # Set the global meter provider
            metrics.set_meter_provider(provider)

            # Create a meter for the service
            meter = metrics.get_meter(service_name)

            # Create counters for main metrics
            prompts_counter = meter.create_counter(
                name="prompts_total", description="Number of prompts processed"
            )

            responses_counter = meter.create_counter(
                name="responses_total", description="Number of responses processed"
            )

            rules_failed_counter = meter.create_counter(
                name="rules_failed", description="Number of rule failures"
            )

            sanitizations_counter = meter.create_counter(
                name="sanitizations_applied",
                description="Number of sanitizations applied",
            )

            llm_checks_counter = meter.create_counter(
                name="llm_checks", description="Number of LLM evaluations performed"
            )

            llm_checks_failed_counter = meter.create_counter(
                name="llm_checks_failed",
                description="Number of LLM evaluations that failed",
            )

            # Create a telemetry handler that updates the OpenTelemetry counters
            def otel_handler(metric_name, value):
                if metric_name == "prompts_total":
                    prompts_counter.add(value)
                elif metric_name == "responses_total":
                    responses_counter.add(value)
                elif metric_name == "rules_failed":
                    rules_failed_counter.add(value)
                elif metric_name == "sanitizations_applied":
                    sanitizations_counter.add(value)
                elif metric_name == "llm_checks":
                    llm_checks_counter.add(value)
                elif metric_name == "llm_checks_failed":
                    llm_checks_failed_counter.add(value)

            # Register the OpenTelemetry handler
            self.register_telemetry_handler(otel_handler)
            self.logger.info(
                f"Configured OpenTelemetry with service name: {service_name}"
            )

        except ImportError:
            self.logger.warning(
                "OpenTelemetry not installed. Please install with 'pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp'"
            )
        except Exception as e:
            self.logger.error(f"Error setting up OpenTelemetry: {str(e)}")
