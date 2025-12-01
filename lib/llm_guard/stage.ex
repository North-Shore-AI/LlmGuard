defmodule LlmGuard.Stage do
  @moduledoc """
  Pipeline stage for LLM security guardrails.

  This module integrates LlmGuard with CrucibleIR pipelines by providing a
  stage implementation that validates inputs and outputs according to
  `CrucibleIR.Reliability.Guardrail` configuration.

  ## Context Requirements

  The stage expects the following in the context:

  - `experiment.reliability.guardrails` - `CrucibleIR.Reliability.Guardrail` struct
  - Either `inputs` or `outputs` - Content to validate (string or list of strings)

  ## Configuration

  The stage reads guardrail configuration from the experiment and converts it
  to LlmGuard configuration. Supported guardrail options:

  - `prompt_injection_detection` - Enable prompt injection detection
  - `jailbreak_detection` - Enable jailbreak detection
  - `pii_detection` - Enable PII detection
  - `pii_redaction` - Enable PII redaction (implies pii_detection)
  - `content_moderation` - Enable content moderation
  - `fail_on_detection` - Return error on threat detection (vs warning)

  ## Usage

  ```elixir
  # Create a guardrail configuration
  guardrail = %CrucibleIR.Reliability.Guardrail{
    profiles: [:default],
    prompt_injection_detection: true,
    jailbreak_detection: true,
    pii_detection: true,
    pii_redaction: false,
    fail_on_detection: true
  }

  # Add to experiment context
  context = %{
    experiment: %{
      reliability: %{
        guardrails: guardrail
      }
    },
    inputs: "User input to validate"
  }

  # Run the stage
  {:ok, updated_context} = LlmGuard.Stage.run(context)

  # Check results
  results = updated_context.guardrails
  # => %{
  #   status: :safe | :detected | :error,
  #   validated_inputs: [...],
  #   detections: [...],
  #   ...
  # }
  ```

  ## Results

  The stage adds a `:guardrails` key to the context with validation results:

  - `status` - Overall status (`:safe`, `:detected`, `:error`)
  - `validated_inputs` or `validated_outputs` - Sanitized content
  - `detections` - List of detected threats (if any)
  - `errors` - List of errors (if any)
  - `config` - LlmGuard config used for validation

  ## Error Handling

  If `fail_on_detection` is `true`, the stage returns `{:error, reason}` when
  threats are detected. Otherwise, it returns `{:ok, context}` with detection
  details in `context.guardrails`.
  """

  alias LlmGuard.Config

  @type context :: map()
  @type stage_opts :: map()
  @type stage_result :: {:ok, context()} | {:error, term()}

  @doc """
  Runs security checks on inputs or outputs.

  Expects context with:
  - `experiment.reliability.guardrails` - Guardrail configuration
  - `inputs` or `outputs` - Content to validate

  Returns updated context with `:guardrails` results, or error if
  `fail_on_detection` is enabled and threats detected.

  ## Parameters

  - `context` - Pipeline context map
  - `opts` - Stage options (currently unused, for future extensibility)

  ## Returns

  - `{:ok, updated_context}` - Validation completed, results in `context.guardrails`
  - `{:error, reason}` - Validation error or threat detected (if `fail_on_detection: true`)

  ## Examples

      iex> guardrail = %CrucibleIR.Reliability.Guardrail{
      ...>   prompt_injection_detection: true,
      ...>   fail_on_detection: false
      ...> }
      iex> context = %{
      ...>   experiment: %{reliability: %{guardrails: guardrail}},
      ...>   inputs: "Safe message"
      ...> }
      iex> {:ok, result} = LlmGuard.Stage.run(context)
      iex> result.guardrails.status
      :safe
  """
  @spec run(context(), stage_opts()) :: stage_result()
  def run(context, opts \\ %{})

  def run(%{experiment: %{reliability: %{guardrails: guardrail_config}}} = context, _opts) do
    # Convert CrucibleIR guardrail config to LlmGuard config
    llm_guard_config = from_ir_config(guardrail_config)

    # Determine what to validate (inputs or outputs)
    cond do
      Map.has_key?(context, :inputs) ->
        validate_inputs(context, llm_guard_config, guardrail_config)

      Map.has_key?(context, :outputs) ->
        validate_outputs(context, llm_guard_config, guardrail_config)

      true ->
        {:error, :no_content_to_validate}
    end
  end

  def run(_context, _opts) do
    {:error, :missing_guardrail_config}
  end

  @doc """
  Describes the stage for pipeline introspection.

  Returns a description of what this stage does and its configuration.

  ## Parameters

  - `opts` - Stage options (currently unused)

  ## Returns

  A map describing the stage.

  ## Examples

      iex> LlmGuard.Stage.describe()
      %{
        name: "LlmGuard Security Stage",
        description: "Validates inputs/outputs for security threats",
        type: :security
      }
  """
  @spec describe(stage_opts()) :: map()
  def describe(_opts \\ %{}) do
    %{
      name: "LlmGuard Security Stage",
      description:
        "Validates inputs/outputs for security threats including prompt injection, jailbreak, and PII",
      type: :security,
      capabilities: [
        :prompt_injection_detection,
        :jailbreak_detection,
        :pii_detection,
        :pii_redaction,
        :content_moderation
      ]
    }
  end

  @doc """
  Converts CrucibleIR Guardrail configuration to LlmGuard Config.

  Maps CrucibleIR guardrail settings to LlmGuard's configuration format.

  ## Parameters

  - `guardrail` - CrucibleIR.Reliability.Guardrail struct

  ## Returns

  LlmGuard.Config struct

  ## Examples

      iex> guardrail = %CrucibleIR.Reliability.Guardrail{
      ...>   prompt_injection_detection: true,
      ...>   pii_detection: true
      ...> }
      iex> config = LlmGuard.Stage.from_ir_config(guardrail)
      iex> config.prompt_injection_detection
      true
  """
  @spec from_ir_config(struct()) :: Config.t()
  def from_ir_config(%{__struct__: _} = guardrail) do
    # Extract options from guardrail config
    options = Map.from_struct(guardrail)

    # Map CrucibleIR options to LlmGuard config
    Config.new(
      prompt_injection_detection: Map.get(options, :prompt_injection_detection, false),
      jailbreak_detection: Map.get(options, :jailbreak_detection, false),
      data_leakage_prevention:
        Map.get(options, :pii_detection, false) || Map.get(options, :pii_redaction, false),
      content_moderation: Map.get(options, :content_moderation, false)
    )
  end

  # Private Functions

  defp validate_inputs(context, config, guardrail_config) do
    inputs = context.inputs
    fail_on_detection = Map.get(guardrail_config, :fail_on_detection, false)
    pii_redaction = Map.get(guardrail_config, :pii_redaction, false)

    # Validate inputs (single string or list)
    results =
      case inputs do
        input when is_binary(input) ->
          [validate_single_input(input, config, pii_redaction)]

        input_list when is_list(input_list) ->
          Enum.map(input_list, &validate_single_input(&1, config, pii_redaction))

        _ ->
          [{:error, :invalid_input_type}]
      end

    # Aggregate results
    {status, validated, detections, errors} = aggregate_results(results)

    guardrails_result = %{
      status: status,
      validated_inputs: validated,
      detections: detections,
      errors: errors,
      config: config
    }

    # Return error if fail_on_detection is true and threats detected
    if fail_on_detection and status == :detected do
      {:error, {:threats_detected, guardrails_result}}
    else
      {:ok, Map.put(context, :guardrails, guardrails_result)}
    end
  end

  defp validate_outputs(context, config, guardrail_config) do
    outputs = context.outputs
    fail_on_detection = Map.get(guardrail_config, :fail_on_detection, false)
    pii_redaction = Map.get(guardrail_config, :pii_redaction, false)

    # Validate outputs (single string or list)
    results =
      case outputs do
        output when is_binary(output) ->
          [validate_single_output(output, config, pii_redaction)]

        output_list when is_list(output_list) ->
          Enum.map(output_list, &validate_single_output(&1, config, pii_redaction))

        _ ->
          [{:error, :invalid_output_type}]
      end

    # Aggregate results
    {status, validated, detections, errors} = aggregate_results(results)

    guardrails_result = %{
      status: status,
      validated_outputs: validated,
      detections: detections,
      errors: errors,
      config: config
    }

    # Return error if fail_on_detection is true and threats detected
    if fail_on_detection and status == :detected do
      {:error, {:threats_detected, guardrails_result}}
    else
      {:ok, Map.put(context, :guardrails, guardrails_result)}
    end
  end

  defp validate_single_input(input, config, pii_redaction) do
    case LlmGuard.validate_input(input, config) do
      {:ok, validated} ->
        if pii_redaction do
          # Apply PII redaction if requested
          apply_pii_redaction(validated)
        else
          {:ok, validated, []}
        end

      {:error, :detected, details} ->
        {:detected, input, details}

      {:error, reason, details} ->
        {:error, reason, details}
    end
  end

  defp validate_single_output(output, config, pii_redaction) do
    case LlmGuard.validate_output(output, config) do
      {:ok, validated} ->
        if pii_redaction do
          # Apply PII redaction if requested
          apply_pii_redaction(validated)
        else
          {:ok, validated, []}
        end

      {:error, :detected, details} ->
        {:detected, output, details}

      {:error, reason, details} ->
        {:error, reason, details}
    end
  end

  defp apply_pii_redaction(text) do
    # Use PIIRedactor if available
    case Code.ensure_loaded?(LlmGuard.Detectors.DataLeakage.PIIRedactor) do
      true ->
        alias LlmGuard.Detectors.DataLeakage.PIIRedactor
        redacted = PIIRedactor.redact(text, strategy: :mask)
        {:ok, redacted, []}

      false ->
        {:ok, text, []}
    end
  end

  defp aggregate_results(results) do
    validated = []
    detections = []
    errors = []

    {validated, detections, errors} =
      Enum.reduce(results, {validated, detections, errors}, fn result, {v_acc, d_acc, e_acc} ->
        case result do
          {:ok, validated_text, []} ->
            {[validated_text | v_acc], d_acc, e_acc}

          {:ok, validated_text, dets} ->
            {[validated_text | v_acc], dets ++ d_acc, e_acc}

          {:detected, _original, details} ->
            {v_acc, [details | d_acc], e_acc}

          {:error, reason, details} ->
            {v_acc, d_acc, [{reason, details} | e_acc]}

          {:error, reason} ->
            {v_acc, d_acc, [{reason, %{}} | e_acc]}
        end
      end)

    # Determine overall status
    status =
      cond do
        length(errors) > 0 -> :error
        length(detections) > 0 -> :detected
        true -> :safe
      end

    {status, Enum.reverse(validated), Enum.reverse(detections), Enum.reverse(errors)}
  end
end
