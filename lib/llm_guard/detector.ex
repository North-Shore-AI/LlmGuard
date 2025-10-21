defmodule LlmGuard.Detector do
  @moduledoc """
  Behaviour for implementing security detectors in LlmGuard.

  All detectors must implement this behaviour to be compatible with the LlmGuard
  security pipeline. Detectors analyze input/output text for security threats
  and return structured results indicating whether threats were detected.

  ## Detection Layers

  LlmGuard uses a multi-layer detection strategy:

  1. **Pattern Matching** (~1ms) - Fast regex-based detection using known patterns
  2. **Heuristic Analysis** (~10ms) - Statistical and structural analysis
  3. **ML Classification** (~50ms) - Transformer-based detection for sophisticated attacks

  ## Result Format

  Detectors must return one of:

  - `{:safe, metadata}` - No threats detected
  - `{:detected, result}` - Threat detected with details

  The detection result map must include:
  - `:confidence` - Float between 0.0 and 1.0 indicating detection confidence
  - `:category` - Atom categorizing the type of threat detected
  - `:patterns_matched` - List of pattern identifiers that matched
  - `:metadata` - Map with additional context about the detection

  ## Examples

      defmodule MyDetector do
        @behaviour LlmGuard.Detector

        @impl true
        def detect(input, opts) do
          if String.contains?(input, "threat") do
            {:detected, %{
              confidence: 0.95,
              category: :custom_threat,
              patterns_matched: ["threat_keyword"],
              metadata: %{reason: "Contains threat keyword"}
            }}
          else
            {:safe, %{checked: true}}
          end
        end

        @impl true
        def name, do: "my_detector"

        @impl true
        def description, do: "Detects custom threats"
      end

  ## Performance Considerations

  Detectors should be designed with performance in mind:
  - Pattern matching should complete in <2ms (P95)
  - Heuristic analysis should complete in <10ms (P95)
  - ML-based detection should complete in <100ms (P95)

  Use early returns and optimize regex patterns for best performance.
  """

  @type input :: String.t()
  @type opts :: keyword()

  @type safe_result :: %{optional(atom()) => any()}

  @type detected_result :: %{
          confidence: float(),
          category: atom(),
          patterns_matched: [String.t()],
          metadata: map()
        }

  @type detection_result :: {:safe, safe_result()} | {:detected, detected_result()}

  @doc """
  Analyzes input text for security threats.

  ## Parameters

  - `input` - The text to analyze (user input, LLM output, etc.)
  - `opts` - Keyword list of options to customize detection behavior

  Common options:
  - `:threshold` - Minimum confidence threshold (default: 0.7)
  - `:enabled` - Whether this detector is enabled (default: true)
  - `:max_patterns` - Maximum number of patterns to check (for performance)

  ## Returns

  - `{:safe, metadata}` - No threats detected
  - `{:detected, result}` - Threat detected with confidence and details
  """
  @callback detect(input, opts) :: detection_result()

  @doc """
  Returns the detector's unique identifier name.

  This should be a short, snake_case string identifying the detector.

  ## Examples

      def name, do: "prompt_injection"
  """
  @callback name() :: String.t()

  @doc """
  Returns a human-readable description of what this detector does.

  ## Examples

      def description, do: "Detects prompt injection attacks using pattern matching"
  """
  @callback description() :: String.t()
end
