defmodule LlmGuard.Pipeline do
  @moduledoc """
  Security pipeline for orchestrating detector execution.

  The pipeline is responsible for:
  - Executing multiple detectors in sequence or parallel
  - Collecting and aggregating detection results
  - Error handling and recovery
  - Performance monitoring and telemetry
  - Early termination on detection

  ## Execution Modes

  ### Sequential Execution (default)
  Detectors run one after another. Supports early termination.

  ### Parallel Execution
  Detectors run concurrently for improved performance.

  ## Configuration Options

  - `:early_termination` - Stop on first detection (default: `true`)
  - `:continue_on_error` - Continue pipeline if detector fails (default: `false`)
  - `:confidence_threshold` - Minimum confidence to consider detection (default: `0.7`)
  - `:timeout` - Maximum time for pipeline execution in ms (default: `5000`)
  - `:parallel` - Execute detectors in parallel (default: `false`)

  ## Examples

      # Run pipeline with default settings
      {:ok, result} = Pipeline.run(input, [Detector1, Detector2], %{})

      # Run with early termination disabled
      {:error, :detected, result} = Pipeline.run(
        input,
        [Detector1, Detector2],
        %{early_termination: false}
      )

      # Run asynchronously
      task = Pipeline.async_run(input, detectors, config)
      result = Task.await(task)
  """

  require Logger

  alias LlmGuard.Cache.PatternCache
  alias LlmGuard.Config

  @type detector :: module()
  @type pipeline_config :: map()

  @type detection :: %{
          detector: String.t(),
          confidence: float(),
          category: atom(),
          patterns_matched: [String.t()],
          metadata: map()
        }

  @type detector_result :: %{
          detector: String.t(),
          result: :safe | :detected | :error,
          duration_ms: non_neg_integer(),
          details: map()
        }

  @type pipeline_result :: %{
          input: String.t(),
          safe?: boolean(),
          detections: [detection()],
          detector_results: [detector_result()],
          total_duration_ms: non_neg_integer(),
          error: map() | nil
        }

  @type run_result ::
          {:ok, pipeline_result()}
          | {:error, :detected, pipeline_result()}
          | {:error, :pipeline_error, pipeline_result()}

  @doc """
  Runs the security pipeline on the given input.

  Executes all configured detectors and returns aggregated results.

  ## Parameters

  - `input` - The text to analyze
  - `detectors` - List of detector modules to execute
  - `config` - Pipeline configuration map

  ## Returns

  - `{:ok, result}` - No threats detected
  - `{:error, :detected, result}` - Threats detected
  - `{:error, :pipeline_error, result}` - Pipeline execution error
  """
  @spec run(String.t(), [detector()], pipeline_config()) :: run_result()
  def run(input, detectors, config \\ %{}) do
    start_time = System.monotonic_time()

    try do
      detector_results = execute_detectors(input, detectors, config)

      total_duration_native = System.monotonic_time() - start_time
      total_duration_ms = System.convert_time_unit(total_duration_native, :native, :millisecond)

      result = build_result(input, detector_results, total_duration_ms, config)

      emit_telemetry(result, detectors, config, total_duration_native)

      categorize_result(result)
    rescue
      error ->
        total_duration_native = System.monotonic_time() - start_time
        total_duration_ms = System.convert_time_unit(total_duration_native, :native, :millisecond)

        error_result = %{
          input: input,
          safe?: false,
          detections: [],
          detector_results: [],
          total_duration_ms: total_duration_ms,
          error: %{
            detector: "pipeline",
            reason: Exception.message(error),
            stacktrace: __STACKTRACE__
          }
        }

        Logger.error("Pipeline error: #{Exception.message(error)}")

        emit_telemetry(error_result, detectors, config, total_duration_native)

        {:error, :pipeline_error, error_result}
    end
  end

  @doc """
  Runs the pipeline asynchronously.

  Returns a `Task` that can be awaited for the result.

  ## Parameters

  - `input` - The text to analyze
  - `detectors` - List of detector modules
  - `config` - Pipeline configuration

  ## Returns

  A `Task` that will yield the pipeline result.

  ## Examples

      task = Pipeline.async_run(input, detectors, config)
      result = Task.await(task, timeout)
  """
  @spec async_run(String.t(), [detector()], pipeline_config()) :: Task.t()
  def async_run(input, detectors, config \\ %{}) do
    Task.async(fn -> run(input, detectors, config) end)
  end

  @doc """
  Sanitizes and validates input before processing.

  ## Parameters

  - `input` - The input string to sanitize
  - `config` - Configuration (can be Config struct or map)

  ## Returns

  - `{:ok, sanitized_input}` - Input is valid
  - `{:error, reason, details}` - Input validation failed
  """
  @spec sanitize_input(String.t(), Config.t() | map()) ::
          {:ok, String.t()} | {:error, atom(), map()}
  def sanitize_input(input, config) when is_binary(input) do
    max_length = get_max_length(config)
    trim_whitespace = Map.get(config, :trim_whitespace, false)

    sanitized =
      if trim_whitespace do
        String.trim(input)
      else
        input
      end

    if String.length(sanitized) > max_length do
      {:error, :input_too_long,
       %{
         max_length: max_length,
         actual_length: String.length(sanitized)
       }}
    else
      {:ok, sanitized}
    end
  end

  # Private Functions

  defp execute_detectors(input, detectors, config) do
    early_termination = Map.get(config, :early_termination, true)
    continue_on_error = Map.get(config, :continue_on_error, false)
    confidence_threshold = Map.get(config, :confidence_threshold, 0.7)
    caching = Map.get(config, :caching)

    Enum.reduce_while(detectors, [], fn detector, acc ->
      result = execute_detector(detector, input, config, caching)

      case result.result do
        :detected ->
          if result.details.confidence >= confidence_threshold do
            results = [result | acc]

            if early_termination do
              {:halt, results}
            else
              {:cont, results}
            end
          else
            {:cont, [result | acc]}
          end

        :error ->
          if continue_on_error do
            {:cont, [result | acc]}
          else
            {:halt, [result | acc]}
          end

        :safe ->
          {:cont, [result | acc]}
      end
    end)
    |> Enum.reverse()
  end

  defp execute_detector(detector, input, _config, caching) do
    use_cache? = cache_enabled?(caching)
    use_result_cache? = use_cache? and Map.get(caching, :result_cache, true)
    cache_available? = use_result_cache? and Process.whereis(PatternCache) != nil
    cache_ttl = Map.get(caching || %{}, :result_ttl_seconds)

    input_hash = if cache_available?, do: PatternCache.hash_input(input), else: nil

    with true <- cache_available?,
         {:ok, cached_result} <- PatternCache.get_result(input_hash, detector.name()) do
      emit_cache_telemetry(:result, true)
      emit_detector_telemetry(cached_result)
      cached_result
    else
      _ ->
        emit_cache_telemetry(:result, false, cache_available?)
        start_time = System.monotonic_time()

        result =
          try do
            case detector.detect(input, []) do
              {:safe, details} ->
                duration_native = System.monotonic_time() - start_time
                duration_ms = System.convert_time_unit(duration_native, :native, :millisecond)

                %{
                  detector: detector.name(),
                  result: :safe,
                  duration_ms: duration_ms,
                  details: details,
                  duration_native: duration_native
                }

              {:detected, details} ->
                duration_native = System.monotonic_time() - start_time
                duration_ms = System.convert_time_unit(duration_native, :native, :millisecond)

                %{
                  detector: detector.name(),
                  result: :detected,
                  duration_ms: duration_ms,
                  details: details,
                  duration_native: duration_native
                }
            end
          rescue
            error ->
              duration_native = System.monotonic_time() - start_time
              duration_ms = System.convert_time_unit(duration_native, :native, :millisecond)

              %{
                detector: detector.name(),
                result: :error,
                duration_ms: duration_ms,
                details: %{
                  error: Exception.message(error),
                  stacktrace: __STACKTRACE__
                },
                duration_native: duration_native
              }
          end

        emit_detector_telemetry(result)

        if cache_available? do
          PatternCache.put_result(input_hash, detector.name(), result, cache_ttl)
        end

        result
    end
  end

  defp build_result(input, detector_results, total_duration, config) do
    confidence_threshold = Map.get(config, :confidence_threshold, 0.7)
    continue_on_error = Map.get(config, :continue_on_error, false)

    detections =
      detector_results
      |> Enum.filter(&(&1.result == :detected))
      |> Enum.filter(&(&1.details.confidence >= confidence_threshold))
      |> Enum.map(fn result ->
        %{
          detector: result.detector,
          confidence: result.details.confidence,
          category: result.details.category,
          patterns_matched: result.details.patterns_matched,
          metadata: result.details.metadata
        }
      end)

    errors =
      detector_results
      |> Enum.filter(&(&1.result == :error))
      |> Enum.map(fn result ->
        %{
          detector: result.detector,
          reason: result.details.error
        }
      end)

    error =
      if continue_on_error do
        nil
      else
        if length(errors) > 0, do: List.first(errors), else: nil
      end

    %{
      input: input,
      safe?: length(detections) == 0 and error == nil,
      detections: detections,
      detector_results: detector_results,
      total_duration_ms: total_duration,
      error: error
    }
  end

  defp categorize_result(%{safe?: true} = result), do: {:ok, result}

  defp categorize_result(%{error: error} = result) when not is_nil(error) do
    {:error, :pipeline_error, result}
  end

  defp categorize_result(%{safe?: false} = result), do: {:error, :detected, result}

  defp emit_telemetry(result, detectors, _config, duration_native) do
    :telemetry.execute(
      [:llm_guard, :pipeline, :complete],
      %{
        duration: duration_native,
        detections: length(result.detections),
        detectors: length(detectors)
      },
      %{
        safe: result.safe?,
        detector_count: length(detectors),
        error: not is_nil(result.error)
      }
    )
  end

  defp emit_detector_telemetry(%{detector: detector, duration_native: duration_native} = result) do
    :telemetry.execute(
      [:llm_guard, :detector, :complete],
      %{duration: duration_native},
      %{
        detector: detector,
        detected: result.result == :detected,
        category: result.details[:category],
        confidence: result.details[:confidence]
      }
    )
  end

  defp emit_detector_telemetry(_), do: :ok

  defp emit_cache_telemetry(cache_type, hit, available \\ true)
  defp emit_cache_telemetry(_cache_type, _hit, false), do: :ok

  defp emit_cache_telemetry(cache_type, hit, true) do
    :telemetry.execute(
      [:llm_guard, :cache, :access],
      %{},
      %{
        cache_type: cache_type,
        hit: hit
      }
    )
  end

  defp cache_enabled?(nil), do: false
  defp cache_enabled?(caching) when is_map(caching), do: Map.get(caching, :enabled, false)
  defp cache_enabled?(_), do: false

  defp get_max_length(%Config{max_input_length: max}), do: max
  defp get_max_length(%{max_input_length: max}), do: max
  defp get_max_length(_), do: 10_000
end
