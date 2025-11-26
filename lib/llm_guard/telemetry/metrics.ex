defmodule LlmGuard.Telemetry.Metrics do
  @moduledoc """
  Enhanced telemetry and metrics collection for LlmGuard.

  Provides comprehensive metrics tracking including:
  - Detection latency percentiles (P50, P95, P99)
  - Detection outcome rates (safe/detected/error)
  - Detector-specific performance metrics
  - Cache hit rates and efficiency
  - Error categorization and tracking

  ## Metrics Emitted

  ### Counter Metrics
  - `llm_guard.requests.total` - Total requests processed
  - `llm_guard.detections.total` - Total detections by category
  - `llm_guard.errors.total` - Total errors by type
  - `llm_guard.cache.hits` - Cache hits by type
  - `llm_guard.cache.misses` - Cache misses by type

  ### Distribution Metrics
  - `llm_guard.request.duration` - Request duration histogram
  - `llm_guard.detector.duration` - Per-detector duration
  - `llm_guard.detection.confidence` - Confidence score distribution

  ## Usage

      # Setup telemetry handlers
      LlmGuard.Telemetry.Metrics.setup()

      # Metrics are automatically emitted during detection

      # Get current metrics snapshot
      metrics = LlmGuard.Telemetry.Metrics.snapshot()

      # Export Prometheus-format metrics
      prometheus = LlmGuard.Telemetry.Metrics.prometheus_metrics()

  ## Integration

  ### Telemetry.Metrics
  ```elixir
  import Telemetry.Metrics

  defp metrics do
    [
      # Counter metrics
      counter("llm_guard.requests.total"),

      # Distribution metrics with percentiles
      distribution("llm_guard.request.duration",
        unit: {:native, :millisecond},
        reporter_options: [
          buckets: [10, 50, 100, 500, 1000, 5000]
        ]
      )
    ]
  end
  ```

  ### Prometheus Integration
  ```elixir
  # In your supervision tree
  children = [
    {TelemetryMetricsPrometheus, metrics: LlmGuard.Telemetry.Metrics.metrics()}
  ]
  ```
  """

  require Logger

  @metrics_table :llm_guard_metrics

  @type snapshot :: %{
          requests: %{
            total: non_neg_integer(),
            safe: non_neg_integer(),
            detected: non_neg_integer(),
            error: non_neg_integer()
          },
          detections: %{
            by_category: map(),
            total: non_neg_integer()
          },
          errors: %{
            total: non_neg_integer()
          },
          cache: %{
            hits: non_neg_integer(),
            misses: non_neg_integer(),
            hit_rate: float()
          },
          latency: %{
            p50: number(),
            p95: number(),
            p99: number(),
            mean: float()
          }
        }

  @doc """
  Sets up telemetry event handlers for LlmGuard metrics.

  Attaches handlers to all LlmGuard telemetry events and initializes
  the metrics storage table.

  ## Returns

  `:ok`
  """
  @spec setup() :: :ok
  def setup do
    # Create ETS table for metrics storage
    _ = :ets.new(@metrics_table, [:named_table, :set, :public, read_concurrency: true])

    # Initialize metrics counters
    initialize_metrics()

    # Attach telemetry handlers
    attach_handlers()

    Logger.info("LlmGuard telemetry metrics initialized")
    :ok
  end

  @doc """
  Returns a snapshot of current metrics.

  ## Returns

  Map containing all current metrics:
  - `:requests` - Request metrics
  - `:detections` - Detection metrics
  - `:errors` - Error metrics
  - `:cache` - Cache metrics
  - `:latency` - Latency percentiles
  """
  @spec snapshot() :: snapshot()
  def snapshot do
    %{
      requests: request_metrics(),
      detections: detection_metrics(),
      errors: error_metrics(),
      cache: cache_metrics(),
      latency: latency_metrics()
    }
  end

  @doc """
  Exports metrics in Prometheus text format.

  ## Returns

  String containing Prometheus-format metrics suitable for scraping.
  """
  @spec prometheus_metrics() :: String.t()
  def prometheus_metrics do
    metrics = snapshot()

    [
      prometheus_counter("llm_guard_requests_total", metrics.requests.total),
      prometheus_counter("llm_guard_requests_safe", metrics.requests.safe),
      prometheus_counter("llm_guard_requests_detected", metrics.requests.detected),
      prometheus_counter("llm_guard_requests_error", metrics.requests.error),
      prometheus_gauge("llm_guard_latency_p50_milliseconds", metrics.latency.p50),
      prometheus_gauge("llm_guard_latency_p95_milliseconds", metrics.latency.p95),
      prometheus_gauge("llm_guard_latency_p99_milliseconds", metrics.latency.p99),
      prometheus_counter("llm_guard_cache_hits_total", metrics.cache.hits),
      prometheus_counter("llm_guard_cache_misses_total", metrics.cache.misses),
      prometheus_gauge("llm_guard_cache_hit_rate", metrics.cache.hit_rate)
    ]
    |> Enum.join("\n")
  end

  @doc """
  Returns Telemetry.Metrics definitions for integration.

  ## Returns

  List of Telemetry.Metrics metric definitions.
  """
  @spec metrics() :: [Telemetry.Metrics.t()]
  def metrics do
    import Telemetry.Metrics

    [
      # Request counters
      counter("llm_guard.requests.total"),
      counter("llm_guard.requests.safe"),
      counter("llm_guard.requests.detected"),
      counter("llm_guard.requests.error"),

      # Detection counters by category
      counter("llm_guard.detections.total",
        tags: [:category, :detector]
      ),

      # Error counters
      counter("llm_guard.errors.total",
        tags: [:detector, :error_type]
      ),

      # Cache metrics
      counter("llm_guard.cache.hits", tags: [:cache_type]),
      counter("llm_guard.cache.misses", tags: [:cache_type]),

      # Latency distribution
      distribution("llm_guard.request.duration",
        unit: {:native, :millisecond},
        tags: [:outcome],
        reporter_options: [
          buckets: [10, 50, 100, 500, 1000, 5000]
        ]
      ),
      distribution("llm_guard.detector.duration",
        unit: {:native, :millisecond},
        tags: [:detector],
        reporter_options: [
          buckets: [1, 5, 10, 50, 100, 500]
        ]
      ),

      # Confidence distribution
      distribution("llm_guard.detection.confidence",
        tags: [:detector, :category],
        reporter_options: [
          buckets: [0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0]
        ]
      )
    ]
  end

  # Private Functions

  defp initialize_metrics do
    # Request counters
    :ets.insert(@metrics_table, {:requests_total, 0})
    :ets.insert(@metrics_table, {:requests_safe, 0})
    :ets.insert(@metrics_table, {:requests_detected, 0})
    :ets.insert(@metrics_table, {:requests_error, 0})

    # Latency samples (circular buffer)
    :ets.insert(@metrics_table, {:latency_samples, []})

    # Detection counters
    :ets.insert(@metrics_table, {:detections, %{}})

    # Error counters
    :ets.insert(@metrics_table, {:errors, %{}})

    # Cache metrics
    :ets.insert(@metrics_table, {:cache_hits, 0})
    :ets.insert(@metrics_table, {:cache_misses, 0})

    :ok
  end

  defp attach_handlers do
    # Attach to pipeline events
    attach_handler(
      "llm-guard-pipeline-complete",
      [:llm_guard, :pipeline, :complete],
      &handle_pipeline_complete/4
    )

    # Attach to detector events
    attach_handler(
      "llm-guard-detector-complete",
      [:llm_guard, :detector, :complete],
      &handle_detector_complete/4
    )

    # Attach to cache events
    attach_handler(
      "llm-guard-cache-access",
      [:llm_guard, :cache, :access],
      &handle_cache_access/4
    )

    :ok
  end

  defp attach_handler(handler_id, event, callback) do
    case :telemetry.attach(handler_id, event, callback, nil) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  defp handle_pipeline_complete(_event, measurements, metadata, _config) do
    # Increment request counter
    increment_counter(:requests_total)

    # Categorize outcome
    if metadata.safe do
      increment_counter(:requests_safe)
    else
      if metadata[:error] do
        increment_counter(:requests_error)
      else
        increment_counter(:requests_detected)
      end
    end

    # Record latency sample
    record_latency(measurements.duration)

    :ok
  end

  defp handle_detector_complete(_event, measurements, metadata, _config) do
    # Record detector-specific metrics
    detector = metadata.detector

    if metadata.detected do
      increment_detection(detector, metadata.category)

      # Record confidence
      if metadata[:confidence] do
        record_confidence(detector, metadata.category, metadata.confidence)
      end
    end

    # Record detector latency
    record_detector_latency(detector, measurements.duration)

    :ok
  end

  defp handle_cache_access(_event, _measurements, metadata, _config) do
    if metadata.hit do
      increment_counter(:cache_hits)
    else
      increment_counter(:cache_misses)
    end

    :ok
  end

  defp increment_counter(counter) do
    _ = :ets.update_counter(@metrics_table, counter, 1, {counter, 0})
    :ok
  end

  defp get_counter(counter) do
    case :ets.lookup(@metrics_table, counter) do
      [{^counter, value}] -> value
      [] -> 0
    end
  end

  defp record_latency(duration_native) do
    duration_ms = System.convert_time_unit(duration_native, :native, :millisecond)
    # Keep last 1000 samples for percentile calculation
    max_samples = 1000

    [{:latency_samples, samples}] = :ets.lookup(@metrics_table, :latency_samples)

    updated_samples =
      [duration_ms | samples]
      |> Enum.take(max_samples)

    :ets.insert(@metrics_table, {:latency_samples, updated_samples})
  end

  defp record_detector_latency(detector, duration_native) do
    duration_ms = System.convert_time_unit(duration_native, :native, :millisecond)
    key = {:detector_latency, detector}

    case :ets.lookup(@metrics_table, key) do
      [{^key, samples}] ->
        updated = [duration_ms | Enum.take(samples, 99)]
        :ets.insert(@metrics_table, {key, updated})

      [] ->
        :ets.insert(@metrics_table, {key, [duration_ms]})
    end
  end

  defp record_confidence(detector, category, confidence) do
    key = {:confidence, detector, category}

    case :ets.lookup(@metrics_table, key) do
      [{^key, samples}] ->
        updated = [confidence | Enum.take(samples, 99)]
        :ets.insert(@metrics_table, {key, updated})

      [] ->
        :ets.insert(@metrics_table, {key, [confidence]})
    end
  end

  defp increment_detection(detector, category) do
    [{:detections, detections}] = :ets.lookup(@metrics_table, :detections)

    key = {detector, category}
    count = Map.get(detections, key, 0)
    updated = Map.put(detections, key, count + 1)

    :ets.insert(@metrics_table, {:detections, updated})
  end

  defp request_metrics do
    %{
      total: get_counter(:requests_total),
      safe: get_counter(:requests_safe),
      detected: get_counter(:requests_detected),
      error: get_counter(:requests_error)
    }
  end

  defp detection_metrics do
    [{:detections, detections}] = :ets.lookup(@metrics_table, :detections)

    %{
      by_category: detections,
      total: Map.values(detections) |> Enum.sum()
    }
  end

  defp error_metrics do
    %{
      total: get_counter(:requests_error)
    }
  end

  defp cache_metrics do
    hits = get_counter(:cache_hits)
    misses = get_counter(:cache_misses)
    total = hits + misses

    hit_rate =
      if total > 0 do
        hits / total
      else
        0.0
      end

    %{
      hits: hits,
      misses: misses,
      hit_rate: hit_rate
    }
  end

  defp latency_metrics do
    [{:latency_samples, samples}] = :ets.lookup(@metrics_table, :latency_samples)

    if Enum.empty?(samples) do
      %{p50: 0.0, p95: 0.0, p99: 0.0, mean: 0.0}
    else
      sorted = Enum.sort(samples)
      count = length(sorted)

      %{
        p50: percentile(sorted, count, 0.50),
        p95: percentile(sorted, count, 0.95),
        p99: percentile(sorted, count, 0.99),
        mean: Enum.sum(samples) / count
      }
    end
  end

  defp percentile(sorted_samples, count, percentile) do
    index = ceil(count * percentile) - 1
    index = max(0, min(index, count - 1))
    Enum.at(sorted_samples, index)
  end

  defp prometheus_counter(name, value) do
    "# TYPE #{name} counter\n#{name} #{value}"
  end

  defp prometheus_gauge(name, value) do
    "# TYPE #{name} gauge\n#{name} #{value}"
  end
end
