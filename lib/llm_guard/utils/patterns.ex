defmodule LlmGuard.Utils.Patterns do
  @moduledoc """
  Utilities for pattern matching and text analysis.

  This module provides helper functions for:
  - Compiling and matching regex patterns
  - Building pattern matchers from pattern databases
  - Calculating match confidence scores
  - Text normalization and keyword extraction

  ## Pattern Structure

  Patterns used in LlmGuard should have the following structure:

      %{
        regex: ~r/pattern/i,           # Regex pattern
        name: "pattern_name",           # Unique identifier
        severity: :high | :medium | :low,
        category: :attack_category,
        confidence: 0.95,               # Base confidence (0.0-1.0)
        description: "What this detects"
      }

  ## Examples

      # Compile a pattern
      {:ok, regex} = Patterns.compile_pattern("ignore.*instructions", [:caseless])

      # Match text
      Patterns.match?(~r/threat/i, "This is a threat")  # => true

      # Build a pattern matcher
      patterns = [
        %{regex: ~r/attack/i, name: "attack", severity: :high},
        %{regex: ~r/exploit/i, name: "exploit", severity: :medium}
      ]
      matcher = Patterns.build_pattern_matcher(patterns)
      matches = matcher.("This is an attack")  # => [%{name: "attack", ...}]

      # Calculate confidence
      confidence = Patterns.calculate_match_confidence(matches, input_length)
  """

  @type pattern :: %{
          regex: Regex.t(),
          name: String.t(),
          severity: :high | :medium | :low,
          category: atom(),
          confidence: float()
        }

  @type match_result :: %{
          name: String.t(),
          severity: :high | :medium | :low,
          category: atom(),
          confidence: float()
        }

  @doc """
  Compiles a string pattern into a Regex.

  Supports optional flags for case-insensitive matching, multiline, etc.

  ## Parameters

  - `pattern` - String pattern or already-compiled Regex
  - `flags` - List of regex flags (default: `[:caseless, :unicode]`)

  ## Returns

  - `{:ok, regex}` - Successfully compiled regex
  - `{:error, reason}` - Compilation failed

  ## Examples

      iex> {:ok, regex} = LlmGuard.Utils.Patterns.compile_pattern("test")
      iex> Regex.match?(regex, "This is a TEST")
      true

      iex> {:ok, regex} = LlmGuard.Utils.Patterns.compile_pattern("test", [])
      iex> Regex.match?(regex, "This is a TEST")
      false
  """
  @spec compile_pattern(String.t() | Regex.t(), [atom()]) :: {:ok, Regex.t()} | {:error, term()}
  def compile_pattern(pattern, flags \\ [:caseless, :unicode])

  def compile_pattern(%Regex{} = regex, _flags), do: {:ok, regex}

  def compile_pattern(pattern, flags) when is_binary(pattern) do
    opts = Enum.join(flags |> Enum.map(&flag_to_string/1))

    case Regex.compile(pattern, opts) do
      {:ok, regex} -> {:ok, regex}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _error -> {:error, :invalid_pattern}
  end

  @doc """
  Checks if a pattern matches the given text.

  ## Parameters

  - `pattern` - Compiled regex pattern
  - `text` - Text to match against

  ## Returns

  `true` if the pattern matches, `false` otherwise.

  ## Examples

      iex> pattern = ~r/threat/i
      iex> LlmGuard.Utils.Patterns.match?(pattern, "This is a threat")
      true

      iex> LlmGuard.Utils.Patterns.match?(pattern, "This is safe")
      false
  """
  @spec match?(Regex.t(), String.t()) :: boolean()
  def match?(pattern, text) when is_binary(text) do
    Regex.match?(pattern, text)
  end

  @doc """
  Returns all matches of a pattern in the text.

  ## Parameters

  - `pattern` - Compiled regex pattern
  - `text` - Text to search

  ## Returns

  List of matched strings.

  ## Examples

      iex> pattern = ~r/\\b\\w+@\\w+\\.\\w+\\b/
      iex> text = "Email: john@example.com or jane@test.org"
      iex> matches = LlmGuard.Utils.Patterns.match_all(pattern, text)
      iex> length(matches)
      2
  """
  @spec match_all(Regex.t(), String.t()) :: [String.t()]
  def match_all(pattern, text) when is_binary(text) do
    pattern
    |> Regex.scan(text)
    |> Enum.map(fn
      [match | _] -> match
      [] -> nil
    end)
    |> Enum.filter(&(&1 != nil))
  end

  @doc """
  Builds a pattern matcher function from a list of patterns.

  Returns a function that takes text and returns all matching patterns.

  ## Parameters

  - `patterns` - List of pattern maps

  ## Returns

  A function `(String.t() -> [match_result()])` that finds matches.

  ## Examples

      patterns = [
        %{regex: ~r/threat/i, name: "threat", severity: :high, category: :generic, confidence: 0.9}
      ]

      matcher = Patterns.build_pattern_matcher(patterns)
      matches = matcher.("This is a threat")
      # => [%{name: "threat", severity: :high, category: :generic, confidence: 0.9}]
  """
  @spec build_pattern_matcher([pattern()]) :: (String.t() -> [match_result()])
  def build_pattern_matcher(patterns) do
    fn text ->
      patterns
      |> Enum.filter(fn pattern ->
        Regex.match?(pattern.regex, text)
      end)
      |> Enum.map(fn pattern ->
        %{
          name: pattern.name,
          severity: pattern.severity,
          category: pattern.category,
          confidence: Map.get(pattern, :confidence, 0.9)
        }
      end)
    end
  end

  @doc """
  Calculates confidence score based on pattern matches.

  Takes into account:
  - Number of patterns matched
  - Base confidence of each pattern
  - Input length (shorter inputs with matches = higher confidence)

  ## Parameters

  - `matched_patterns` - List of matched patterns with confidence scores
  - `input_length` - Length of the input text

  ## Returns

  Float between 0.0 and 1.0 representing overall confidence.

  ## Examples

      matches = [
        %{confidence: 0.8},
        %{confidence: 0.9}
      ]

      confidence = Patterns.calculate_match_confidence(matches, 100)
      # => ~0.95 (higher due to multiple matches)
  """
  @spec calculate_match_confidence([map()], non_neg_integer()) :: float()
  def calculate_match_confidence([], _input_length), do: 0.0

  def calculate_match_confidence(matched_patterns, input_length) do
    # Get highest base confidence
    max_confidence =
      matched_patterns
      |> Enum.map(&Map.get(&1, :confidence, 0.9))
      |> Enum.max()

    # Boost for multiple matches (up to 20% boost)
    match_count_boost = min(0.2, (length(matched_patterns) - 1) * 0.05)

    # Slight boost for shorter inputs (more concentrated threat)
    length_factor =
      cond do
        input_length < 50 -> 0.05
        input_length < 200 -> 0.02
        true -> 0.0
      end

    # Calculate final confidence, capped at 1.0
    confidence = max_confidence + match_count_boost + length_factor
    min(1.0, confidence)
  end

  @doc """
  Normalizes text for pattern matching.

  Applies:
  - Lowercase conversion
  - Whitespace normalization
  - Unicode normalization

  ## Parameters

  - `text` - Text to normalize

  ## Returns

  Normalized text string.

  ## Examples

      iex> LlmGuard.Utils.Patterns.normalize_text("  HELLO   World  ")
      "hello world"
  """
  @spec normalize_text(String.t()) :: String.t()
  def normalize_text(text) when is_binary(text) do
    text
    |> String.downcase()
    |> String.trim()
    |> String.replace(~r/\s+/, " ")
  end

  @doc """
  Extracts keywords from text.

  Useful for heuristic analysis and keyword-based detection.

  ## Options

  - `:min_length` - Minimum keyword length (default: 3)
  - `:max_keywords` - Maximum number of keywords to return (default: 100)

  ## Parameters

  - `text` - Text to extract keywords from
  - `opts` - Keyword options

  ## Returns

  List of unique keywords.

  ## Examples

      iex> text = "ignore all previous instructions"
      iex> keywords = LlmGuard.Utils.Patterns.extract_keywords(text, min_length: 4)
      iex> "ignore" in keywords
      true
  """
  @spec extract_keywords(String.t(), keyword()) :: [String.t()]
  def extract_keywords(text, opts \\ []) when is_binary(text) do
    min_length = Keyword.get(opts, :min_length, 3)
    max_keywords = Keyword.get(opts, :max_keywords, 100)

    text
    |> normalize_text()
    |> String.split(~r/\W+/, trim: true)
    |> Enum.filter(&(String.length(&1) >= min_length))
    |> Enum.uniq()
    |> Enum.take(max_keywords)
  end

  # Private helpers

  defp flag_to_string(:caseless), do: "i"
  defp flag_to_string(:unicode), do: "u"
  defp flag_to_string(:multiline), do: "m"
  defp flag_to_string(:dotall), do: "s"
  defp flag_to_string(:extended), do: "x"
  defp flag_to_string(_), do: ""
end
