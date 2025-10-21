defmodule LlmGuard.ConfigTest do
  @moduledoc """
  Tests for LlmGuard.Config module.

  Validates configuration creation, validation, merging, and defaults.
  """
  use ExUnit.Case, async: true

  alias LlmGuard.Config

  describe "new/1" do
    test "creates default configuration" do
      config = Config.new()

      assert config.prompt_injection_detection == true
      assert config.jailbreak_detection == true
      assert config.data_leakage_prevention == true
      assert config.content_moderation == true
      assert config.confidence_threshold == 0.7
      assert config.max_input_length == 10_000
      assert config.max_output_length == 10_000
    end

    test "merges custom configuration" do
      config = Config.new(confidence_threshold: 0.9, max_input_length: 5000)

      assert config.confidence_threshold == 0.9
      assert config.max_input_length == 5000
      # Other defaults preserved
      assert config.prompt_injection_detection == true
    end

    test "validates confidence_threshold range" do
      assert_raise ArgumentError, ~r/confidence_threshold must be between 0.0 and 1.0/, fn ->
        Config.new(confidence_threshold: 1.5)
      end

      assert_raise ArgumentError, ~r/confidence_threshold must be between 0.0 and 1.0/, fn ->
        Config.new(confidence_threshold: -0.1)
      end
    end

    test "validates max_input_length is positive" do
      assert_raise ArgumentError, ~r/max_input_length must be positive/, fn ->
        Config.new(max_input_length: 0)
      end

      assert_raise ArgumentError, ~r/max_input_length must be positive/, fn ->
        Config.new(max_input_length: -100)
      end
    end

    test "validates max_output_length is positive" do
      assert_raise ArgumentError, ~r/max_output_length must be positive/, fn ->
        Config.new(max_output_length: 0)
      end
    end

    test "validates enabled_detectors is a list" do
      assert_raise ArgumentError, ~r/enabled_detectors must be a list/, fn ->
        Config.new(enabled_detectors: "invalid")
      end
    end

    test "accepts valid boolean flags" do
      config =
        Config.new(
          prompt_injection_detection: false,
          jailbreak_detection: false,
          data_leakage_prevention: false,
          content_moderation: false
        )

      assert config.prompt_injection_detection == false
      assert config.jailbreak_detection == false
      assert config.data_leakage_prevention == false
      assert config.content_moderation == false
    end
  end

  describe "update/2" do
    test "updates existing configuration" do
      config = Config.new()
      updated = Config.update(config, confidence_threshold: 0.8)

      assert updated.confidence_threshold == 0.8
      # Original unchanged
      assert config.confidence_threshold == 0.7
    end

    test "validates updates" do
      config = Config.new()

      assert_raise ArgumentError, fn ->
        Config.update(config, confidence_threshold: 2.0)
      end
    end
  end

  describe "get/2 and get/3" do
    test "retrieves configuration value" do
      config = Config.new(confidence_threshold: 0.85)

      assert Config.get(config, :confidence_threshold) == 0.85
      assert Config.get(config, :prompt_injection_detection) == true
    end

    test "returns default value if key missing" do
      config = Config.new()

      assert Config.get(config, :nonexistent_key, :default_value) == :default_value
    end

    test "returns nil if key missing and no default" do
      config = Config.new()

      assert Config.get(config, :nonexistent_key) == nil
    end
  end

  describe "enabled_detectors/1" do
    test "returns list of enabled detector types" do
      config = Config.new()
      detectors = Config.enabled_detectors(config)

      assert is_list(detectors)
      assert :prompt_injection in detectors
      assert :jailbreak in detectors
      assert :data_leakage in detectors
      assert :content_safety in detectors
    end

    test "excludes disabled detectors" do
      config = Config.new(prompt_injection_detection: false, jailbreak_detection: false)
      detectors = Config.enabled_detectors(config)

      refute :prompt_injection in detectors
      refute :jailbreak in detectors
      assert :data_leakage in detectors
    end

    test "includes custom detectors if specified" do
      config = Config.new(enabled_detectors: [:custom_detector])
      detectors = Config.enabled_detectors(config)

      assert :custom_detector in detectors
    end
  end

  describe "rate_limit_config/1" do
    test "returns rate limiting configuration" do
      config =
        Config.new(
          rate_limiting: %{
            requests_per_minute: 60,
            tokens_per_minute: 100_000
          }
        )

      rate_config = Config.rate_limit_config(config)

      assert rate_config.requests_per_minute == 60
      assert rate_config.tokens_per_minute == 100_000
    end

    test "returns nil if rate limiting not configured" do
      config = Config.new()

      assert Config.rate_limit_config(config) == nil
    end
  end

  describe "audit_config/1" do
    test "returns audit configuration" do
      config =
        Config.new(
          audit_logging: %{
            enabled: true,
            backend: :ets,
            log_safe_inputs: false
          }
        )

      audit_config = Config.audit_config(config)

      assert audit_config.enabled == true
      assert audit_config.backend == :ets
      assert audit_config.log_safe_inputs == false
    end

    test "returns nil if audit not configured" do
      config = Config.new()

      assert Config.audit_config(config) == nil
    end
  end

  describe "to_map/1" do
    test "converts config struct to map" do
      config = Config.new(confidence_threshold: 0.95)
      map = Config.to_map(config)

      assert is_map(map)
      assert map.confidence_threshold == 0.95
      assert map.prompt_injection_detection == true
    end
  end

  describe "from_map/1" do
    test "creates config from map" do
      map = %{
        confidence_threshold: 0.88,
        max_input_length: 8000,
        prompt_injection_detection: false
      }

      config = Config.from_map(map)

      assert config.confidence_threshold == 0.88
      assert config.max_input_length == 8000
      assert config.prompt_injection_detection == false
    end

    test "validates values when creating from map" do
      map = %{confidence_threshold: 5.0}

      assert_raise ArgumentError, fn ->
        Config.from_map(map)
      end
    end
  end
end
