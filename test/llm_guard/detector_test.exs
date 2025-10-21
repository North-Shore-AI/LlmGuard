defmodule LlmGuard.DetectorTest do
  @moduledoc """
  Tests for the LlmGuard.Detector behaviour.

  This test suite validates that the detector behaviour is correctly defined
  and that modules implementing it conform to the expected interface.
  """
  use ExUnit.Case, async: true

  defmodule TestDetector do
    @moduledoc false
    @behaviour LlmGuard.Detector

    @impl LlmGuard.Detector
    def detect(_input, _opts) do
      {:safe, %{checked: true}}
    end

    @impl LlmGuard.Detector
    def name, do: "test_detector"

    @impl LlmGuard.Detector
    def description, do: "A test detector for validation"
  end

  defmodule AlwaysDetectDetector do
    @moduledoc false
    @behaviour LlmGuard.Detector

    @impl LlmGuard.Detector
    def detect(_input, _opts) do
      {:detected,
       %{
         confidence: 0.95,
         category: :test_threat,
         patterns_matched: ["test_pattern"],
         metadata: %{reason: "always detects for testing"}
       }}
    end

    @impl LlmGuard.Detector
    def name, do: "always_detect"

    @impl LlmGuard.Detector
    def description, do: "Always detects threats for testing"
  end

  describe "detector behaviour implementation" do
    test "detector can return safe result" do
      assert {:safe, result} = TestDetector.detect("benign input", [])
      assert is_map(result)
    end

    test "detector can return detected result" do
      assert {:detected, result} = AlwaysDetectDetector.detect("any input", [])
      assert is_map(result)
      assert result.confidence >= 0.0 and result.confidence <= 1.0
      assert is_atom(result.category)
      assert is_list(result.patterns_matched)
      assert is_map(result.metadata)
    end

    test "detector has name/0 callback" do
      assert TestDetector.name() == "test_detector"
      assert is_binary(TestDetector.name())
    end

    test "detector has description/0 callback" do
      assert is_binary(TestDetector.description())
    end
  end

  describe "detection result structure" do
    test "safe result contains metadata" do
      {:safe, result} = TestDetector.detect("input", [])
      assert is_map(result)
    end

    test "detected result has required fields" do
      {:detected, result} = AlwaysDetectDetector.detect("input", [])

      assert Map.has_key?(result, :confidence)
      assert Map.has_key?(result, :category)
      assert Map.has_key?(result, :patterns_matched)
      assert Map.has_key?(result, :metadata)
    end

    test "confidence is between 0 and 1" do
      {:detected, result} = AlwaysDetectDetector.detect("input", [])
      assert result.confidence >= 0.0
      assert result.confidence <= 1.0
    end

    test "patterns_matched is a list" do
      {:detected, result} = AlwaysDetectDetector.detect("input", [])
      assert is_list(result.patterns_matched)
    end
  end

  describe "detector options" do
    test "detector accepts options" do
      assert {:safe, _} = TestDetector.detect("input", threshold: 0.8)
    end

    test "detector can use options to customize behavior" do
      # This will be more meaningful when we have actual detectors
      assert {:safe, _} = TestDetector.detect("input", enabled: false)
    end
  end
end
