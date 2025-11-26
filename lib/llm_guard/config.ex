defmodule LlmGuard.Config do
  @moduledoc """
  Configuration management for LlmGuard.

  This module provides a centralized configuration system for all LlmGuard
  security features, including detection toggles, thresholds, rate limiting,
  and audit logging.

  ## Configuration Options

  ### Detection Toggles
  - `:prompt_injection_detection` - Enable/disable prompt injection detection (default: `true`)
  - `:jailbreak_detection` - Enable/disable jailbreak detection (default: `true`)
  - `:data_leakage_prevention` - Enable/disable data leakage prevention (default: `true`)
  - `:content_moderation` - Enable/disable content moderation (default: `true`)

  ### Thresholds
  - `:confidence_threshold` - Minimum confidence for detection (0.0-1.0, default: `0.7`)
  - `:max_input_length` - Maximum input length in characters (default: `10_000`)
  - `:max_output_length` - Maximum output length in characters (default: `10_000`)

  ### Custom Detectors
  - `:enabled_detectors` - List of custom detector modules to enable (default: `[]`)

  ### Rate Limiting
  - `:rate_limiting` - Map with rate limiting configuration:
    - `:requests_per_minute` - Maximum requests per minute
    - `:tokens_per_minute` - Maximum tokens per minute
    - `:strategy` - Rate limiting strategy (`:token_bucket`, `:sliding_window`)

  ### Audit Logging
  - `:audit_logging` - Map with audit configuration:
    - `:enabled` - Enable audit logging (default: `false`)
    - `:backend` - Backend to use (`:ets`, `:database`, `:external`)
    - `:log_safe_inputs` - Whether to log inputs that pass validation (default: `false`)

  ### Caching
  - `:caching` - Map with caching configuration:
    - `:enabled` - Enable pattern and result caching (default: `false`)
    - `:pattern_cache` - Enable compiled pattern caching (default: `true`)
    - `:result_cache` - Enable detection result caching (default: `true`)
    - `:result_ttl_seconds` - TTL for cached results (default: `300`)
    - `:max_cache_entries` - Maximum cached results (default: `10_000`)

  ## Examples

      # Create default configuration
      config = LlmGuard.Config.new()

      # Create custom configuration
      config = LlmGuard.Config.new(
        confidence_threshold: 0.85,
        max_input_length: 5000,
        prompt_injection_detection: true,
        rate_limiting: %{
          requests_per_minute: 100,
          tokens_per_minute: 200_000
        }
      )

      # Update existing configuration
      updated = LlmGuard.Config.update(config, confidence_threshold: 0.9)

      # Get configuration value
      threshold = LlmGuard.Config.get(config, :confidence_threshold)

      # Get list of enabled detectors
      detectors = LlmGuard.Config.enabled_detectors(config)
  """

  @type t :: %__MODULE__{
          prompt_injection_detection: boolean(),
          jailbreak_detection: boolean(),
          data_leakage_prevention: boolean(),
          content_moderation: boolean(),
          confidence_threshold: float(),
          max_input_length: pos_integer(),
          max_output_length: pos_integer(),
          enabled_detectors: [atom()],
          rate_limiting: map() | nil,
          audit_logging: map() | nil,
          caching: map() | nil,
          custom_options: map()
        }

  @enforce_keys []
  defstruct prompt_injection_detection: true,
            jailbreak_detection: true,
            data_leakage_prevention: true,
            content_moderation: true,
            confidence_threshold: 0.7,
            max_input_length: 10_000,
            max_output_length: 10_000,
            enabled_detectors: [],
            rate_limiting: nil,
            audit_logging: nil,
            caching: nil,
            custom_options: %{}

  @doc """
  Creates a new configuration with the given options.

  Merges provided options with defaults and validates all values.

  ## Parameters

  - `opts` - Keyword list of configuration options

  ## Returns

  A validated `Config` struct.

  ## Raises

  `ArgumentError` if any configuration value is invalid.

  ## Examples

      iex> config = LlmGuard.Config.new()
      iex> config.confidence_threshold
      0.7

      iex> config = LlmGuard.Config.new(confidence_threshold: 0.85)
      iex> config.confidence_threshold
      0.85
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    config = struct!(__MODULE__, opts)
    validate!(config)
    config
  end

  @doc """
  Updates an existing configuration with new values.

  Returns a new configuration struct with the updates applied.
  The original configuration is not modified.

  ## Parameters

  - `config` - Existing configuration struct
  - `updates` - Keyword list of updates to apply

  ## Returns

  A new validated `Config` struct with updates applied.

  ## Examples

      iex> config = LlmGuard.Config.new()
      iex> updated = LlmGuard.Config.update(config, confidence_threshold: 0.9)
      iex> updated.confidence_threshold
      0.9
  """
  @spec update(t(), keyword()) :: t()
  def update(%__MODULE__{} = config, updates) do
    updated = struct!(config, updates)
    validate!(updated)
    updated
  end

  @doc """
  Gets a configuration value by key.

  Returns the value if the key exists, otherwise returns the default value.

  ## Parameters

  - `config` - Configuration struct
  - `key` - Key to retrieve
  - `default` - Default value if key doesn't exist (default: `nil`)

  ## Examples

      iex> config = LlmGuard.Config.new(confidence_threshold: 0.8)
      iex> LlmGuard.Config.get(config, :confidence_threshold)
      0.8

      iex> LlmGuard.Config.get(config, :missing_key, :default)
      :default
  """
  @spec get(t(), atom(), any()) :: any()
  def get(%__MODULE__{} = config, key, default \\ nil) do
    Map.get(config, key, default)
  end

  @doc """
  Returns a list of enabled detector types based on configuration.

  Combines built-in detector flags with custom enabled detectors.

  ## Parameters

  - `config` - Configuration struct

  ## Returns

  List of detector type atoms.

  ## Examples

      iex> config = LlmGuard.Config.new()
      iex> detectors = LlmGuard.Config.enabled_detectors(config)
      iex> :prompt_injection in detectors
      true
  """
  @spec enabled_detectors(t()) :: [atom()]
  def enabled_detectors(%__MODULE__{} = config) do
    built_in =
      []
      |> maybe_add(:prompt_injection, config.prompt_injection_detection)
      |> maybe_add(:jailbreak, config.jailbreak_detection)
      |> maybe_add(:data_leakage, config.data_leakage_prevention)
      |> maybe_add(:content_safety, config.content_moderation)

    built_in ++ config.enabled_detectors
  end

  @doc """
  Returns the rate limiting configuration if configured.

  ## Parameters

  - `config` - Configuration struct

  ## Returns

  Rate limiting configuration map or `nil` if not configured.
  """
  @spec rate_limit_config(t()) :: map() | nil
  def rate_limit_config(%__MODULE__{rate_limiting: rate_limiting}) do
    case rate_limiting do
      nil -> nil
      config when is_map(config) -> atomize_keys(config)
    end
  end

  @doc """
  Returns the audit logging configuration if configured.

  ## Parameters

  - `config` - Configuration struct

  ## Returns

  Audit configuration map or `nil` if not configured.
  """
  @spec audit_config(t()) :: map() | nil
  def audit_config(%__MODULE__{audit_logging: audit_logging}) do
    case audit_logging do
      nil -> nil
      config when is_map(config) -> atomize_keys(config)
    end
  end

  @doc """
  Returns the caching configuration if configured.

  ## Parameters

  - `config` - Configuration struct

  ## Returns

  Caching configuration map or `nil` if not configured.
  """
  @spec caching_config(t()) :: map() | nil
  def caching_config(%__MODULE__{caching: caching}) do
    case caching do
      nil -> nil
      config when is_map(config) -> atomize_keys(config)
    end
  end

  @doc """
  Checks if caching is enabled.

  ## Parameters

  - `config` - Configuration struct

  ## Returns

  `true` if caching is enabled, `false` otherwise.
  """
  @spec caching_enabled?(t()) :: boolean()
  def caching_enabled?(%__MODULE__{caching: caching}) do
    case caching do
      nil ->
        false

      config when is_map(config) ->
        Map.get(config, :enabled, false) || Map.get(config, "enabled", false)
    end
  end

  @doc """
  Converts a configuration struct to a map.

  ## Parameters

  - `config` - Configuration struct

  ## Returns

  Map representation of the configuration.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = config) do
    Map.from_struct(config)
  end

  @doc """
  Creates a configuration from a map.

  ## Parameters

  - `map` - Map with configuration values

  ## Returns

  A validated `Config` struct.
  """
  @spec from_map(map()) :: t()
  def from_map(map) when is_map(map) do
    opts = Map.to_list(map)
    new(opts)
  end

  # Private Functions

  defp validate!(%__MODULE__{} = config) do
    validate_confidence_threshold!(config.confidence_threshold)
    validate_max_length!(:max_input_length, config.max_input_length)
    validate_max_length!(:max_output_length, config.max_output_length)
    validate_enabled_detectors!(config.enabled_detectors)
    :ok
  end

  defp validate_confidence_threshold!(threshold) do
    unless is_float(threshold) or is_integer(threshold) do
      raise ArgumentError, "confidence_threshold must be a number"
    end

    unless threshold >= 0.0 and threshold <= 1.0 do
      raise ArgumentError,
            "confidence_threshold must be between 0.0 and 1.0, got: #{threshold}"
    end
  end

  defp validate_max_length!(field, value) do
    unless is_integer(value) and value > 0 do
      raise ArgumentError, "#{field} must be positive integer, got: #{inspect(value)}"
    end
  end

  defp validate_enabled_detectors!(detectors) do
    unless is_list(detectors) do
      raise ArgumentError, "enabled_detectors must be a list, got: #{inspect(detectors)}"
    end
  end

  defp maybe_add(list, item, true), do: [item | list]
  defp maybe_add(list, _item, false), do: list

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {key, value} when is_binary(key) -> {String.to_atom(key), value}
      {key, value} when is_atom(key) -> {key, value}
    end)
  end
end
