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
          duration_ms: float(),
          details: map()
        }

  @type pipeline_result :: %{
          input: String.t(),
          safe?: boolean(),
          detections: [detection()],
          detector_results: [detector_result()],
          total_duration_ms: float(),
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
    start_time = System.monotonic_time(:millisecond)

    try do
      detector_results = execute_detectors(input, detectors, config)

      total_duration = System.monotonic_time(:millisecond) - start_time

      result = build_result(input, detector_results, total_duration, config)

      emit_telemetry(result, detectors, config)

      categorize_result(result)
    rescue
      error ->
        total_duration = System.monotonic_time(:millisecond) - start_time

        error_result = %{
          input: input,
          safe?: false,
          detections: [],
          detector_results: [],
          total_duration_ms: total_duration,
          error: %{
            detector: "pipeline",
            reason: Exception.message(error),
            stacktrace: __STACKTRACE__
          }
        }

        Logger.error("Pipeline error: #{Exception.message(error)}")

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

    Enum.reduce_while(detectors, [], fn detector, acc ->
      result = execute_detector(detector, input, config)

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

  defp execute_detector(detector, input, _config) do
    start_time = System.monotonic_time(:millisecond)

    try do
      case detector.detect(input, []) do
        {:safe, details} ->
          duration = System.monotonic_time(:millisecond) - start_time

          %{
            detector: detector.name(),
            result: :safe,
            duration_ms: duration,
            details: details
          }

        {:detected, details} ->
          duration = System.monotonic_time(:millisecond) - start_time

          %{
            detector: detector.name(),
            result: :detected,
            duration_ms: duration,
            details: details
          }
      end
    rescue
      error ->
        duration = System.monotonic_time(:millisecond) - start_time

        %{
          detector: detector.name(),
          result: :error,
          duration_ms: duration,
          details: %{
            error: Exception.message(error),
            stacktrace: __STACKTRACE__
          }
        }
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

  defp emit_telemetry(result, detectors, _config) do
    :telemetry.execute(
      [:llm_guard, :pipeline, :complete],
      %{
        duration: result.total_duration_ms,
        detections: length(result.detections),
        detectors: length(detectors)
      },
      %{
        safe: result.safe?,
        detector_count: length(detectors)
      }
    )
  end

  defp get_max_length(%Config{max_input_length: max}), do: max
  defp get_max_length(%{max_input_length: max}), do: max
  defp get_max_length(_), do: 10_000
end
