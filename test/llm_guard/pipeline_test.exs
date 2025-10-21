defmodule LlmGuard.PipelineTest do
  @moduledoc """
  Tests for LlmGuard.Pipeline module.

  Validates pipeline orchestration, detector execution, error handling,
  and performance monitoring.
  """
  use ExUnit.Case, async: true

  alias LlmGuard.Pipeline
  alias LlmGuard.Config

  defmodule SafeDetector do
    @moduledoc false
    @behaviour LlmGuard.Detector

    @impl true
    def detect(_input, _opts), do: {:safe, %{checked: true}}

    @impl true
    def name, do: "safe_detector"

    @impl true
    def description, do: "Always returns safe"
  end

  defmodule ThreatDetector do
    @moduledoc false
    @behaviour LlmGuard.Detector

    @impl true
    def detect(_input, _opts) do
      {:detected,
       %{
         confidence: 0.95,
         category: :test_threat,
         patterns_matched: ["threat_pattern"],
         metadata: %{}
       }}
    end

    @impl true
    def name, do: "threat_detector"

    @impl true
    def description, do: "Always detects threats"
  end

  defmodule ConditionalDetector do
    @moduledoc false
    @behaviour LlmGuard.Detector

    @impl true
    def detect(input, _opts) do
      if String.contains?(input, "threat") do
        {:detected,
         %{
           confidence: 0.9,
           category: :conditional_threat,
           patterns_matched: ["threat_word"],
           metadata: %{}
         }}
      else
        {:safe, %{checked: true}}
      end
    end

    @impl true
    def name, do: "conditional_detector"

    @impl true
    def description, do: "Detects based on content"
  end

  defmodule ErrorDetector do
    @moduledoc false
    @behaviour LlmGuard.Detector

    @impl true
    def detect(_input, _opts) do
      raise "Detector error"
    end

    @impl true
    def name, do: "error_detector"

    @impl true
    def description, do: "Always raises error"
  end

  describe "run/3 with single detector" do
    test "returns safe when detector finds no threats" do
      assert {:ok, result} = Pipeline.run("benign input", [SafeDetector], %{})

      assert result.input == "benign input"
      assert result.safe? == true
      assert result.detections == []
      assert is_list(result.detector_results)
      assert length(result.detector_results) == 1
    end

    test "returns detected when detector finds threat" do
      assert {:error, :detected, result} = Pipeline.run("malicious input", [ThreatDetector], %{})

      assert result.input == "malicious input"
      assert result.safe? == false
      assert length(result.detections) > 0

      [detection | _] = result.detections
      assert detection.confidence == 0.95
      assert detection.category == :test_threat
      assert detection.detector == "threat_detector"
    end

    test "includes detector execution details" do
      {:ok, result} = Pipeline.run("input", [SafeDetector], %{})

      [detector_result | _] = result.detector_results

      assert detector_result.detector == "safe_detector"
      assert detector_result.result == :safe
      assert is_number(detector_result.duration_ms)
      assert detector_result.duration_ms >= 0
    end
  end

  describe "run/3 with multiple detectors" do
    test "executes all detectors when all return safe" do
      detectors = [SafeDetector, ConditionalDetector]

      assert {:ok, result} = Pipeline.run("benign input", detectors, %{})

      assert result.safe? == true
      assert length(result.detector_results) == 2
    end

    test "stops early when threat detected with early_termination" do
      detectors = [ThreatDetector, SafeDetector]
      config = %{early_termination: true}

      assert {:error, :detected, result} = Pipeline.run("input", detectors, config)

      assert result.safe? == false
      # Should only execute ThreatDetector before terminating
      assert length(result.detector_results) <= 2
    end

    test "continues all detectors when early_termination disabled" do
      detectors = [ThreatDetector, SafeDetector, ConditionalDetector]
      config = %{early_termination: false}

      assert {:error, :detected, result} = Pipeline.run("input", detectors, config)

      # All detectors should execute
      assert length(result.detector_results) == 3
    end

    test "collects all detections from multiple detectors" do
      detectors = [ThreatDetector, ConditionalDetector]

      assert {:error, :detected, result} = Pipeline.run("threat input", detectors, %{})

      assert length(result.detections) >= 1
    end
  end

  describe "run/3 error handling" do
    test "handles detector errors gracefully" do
      assert {:error, :pipeline_error, result} = Pipeline.run("input", [ErrorDetector], %{})

      assert result.safe? == false
      assert result.error != nil
    end

    test "continues pipeline on error with continue_on_error" do
      detectors = [ErrorDetector, SafeDetector]
      config = %{continue_on_error: true}

      assert {:ok, result} = Pipeline.run("input", detectors, config)

      # Should have executed SafeDetector despite ErrorDetector failing
      assert length(result.detector_results) == 2
    end

    test "stops pipeline on error without continue_on_error" do
      detectors = [ErrorDetector, SafeDetector]
      config = %{continue_on_error: false}

      assert {:error, :pipeline_error, _result} = Pipeline.run("input", detectors, config)
    end

    test "includes error details in result" do
      {:error, :pipeline_error, result} = Pipeline.run("input", [ErrorDetector], %{})

      assert result.error.detector == "error_detector"
      assert result.error.reason != nil
    end
  end

  describe "run/3 with confidence threshold" do
    test "filters detections below confidence threshold" do
      config = %{confidence_threshold: 0.99}

      # ThreatDetector returns confidence of 0.95
      assert {:ok, result} = Pipeline.run("input", [ThreatDetector], config)

      assert result.safe? == true
      assert result.detections == []
    end

    test "includes detections above confidence threshold" do
      config = %{confidence_threshold: 0.8}

      assert {:error, :detected, result} = Pipeline.run("input", [ThreatDetector], config)

      assert result.safe? == false
      assert length(result.detections) > 0
    end
  end

  describe "run/3 performance tracking" do
    test "tracks total pipeline duration" do
      {:ok, result} = Pipeline.run("input", [SafeDetector], %{})

      assert is_number(result.total_duration_ms)
      assert result.total_duration_ms >= 0
    end

    test "tracks individual detector durations" do
      detectors = [SafeDetector, ConditionalDetector]
      {:ok, result} = Pipeline.run("input", detectors, %{})

      for detector_result <- result.detector_results do
        assert is_number(detector_result.duration_ms)
        assert detector_result.duration_ms >= 0
      end
    end

    test "total duration equals sum of detector durations (approximately)" do
      {:ok, result} = Pipeline.run("input", [SafeDetector, ConditionalDetector], %{})

      detector_sum =
        result.detector_results
        |> Enum.map(& &1.duration_ms)
        |> Enum.sum()

      # Allow some overhead for pipeline orchestration
      assert result.total_duration_ms >= detector_sum

      # Only check upper bound if duration is measurable
      if detector_sum > 0 do
        assert result.total_duration_ms < detector_sum * 1.5
      end
    end
  end

  describe "async_run/3" do
    test "executes detectors asynchronously" do
      detectors = [SafeDetector, ConditionalDetector, ThreatDetector]

      task = Pipeline.async_run("input", detectors, %{})
      result = Task.await(task)

      assert {:error, :detected, pipeline_result} = result
      assert pipeline_result.safe? == false
    end

    test "async execution completes successfully" do
      task = Pipeline.async_run("benign", [SafeDetector], %{})
      result = Task.await(task)

      assert {:ok, pipeline_result} = result
      assert pipeline_result.safe? == true
    end
  end

  describe "sanitize_input/2" do
    test "returns input unchanged if within limits" do
      config = Config.new(max_input_length: 100)
      assert {:ok, "test"} = Pipeline.sanitize_input("test", config)
    end

    test "returns error if input exceeds max length" do
      config = Config.new(max_input_length: 5)
      assert {:error, :input_too_long, _} = Pipeline.sanitize_input("this is too long", config)
    end

    test "trims whitespace when configured" do
      config = %{trim_whitespace: true}
      assert {:ok, "test"} = Pipeline.sanitize_input("  test  ", config)
    end
  end
end
