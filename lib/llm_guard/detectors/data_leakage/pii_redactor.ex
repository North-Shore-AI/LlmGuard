defmodule LlmGuard.Detectors.DataLeakage.PIIRedactor do
  @moduledoc """
  Redacts PII from text using various strategies.

  Supports multiple redaction strategies:
  - `:mask` - Replace with asterisks (default)
  - `:partial` - Show partial information (e.g., last 4 digits)
  - `:hash` - Replace with deterministic hash
  - `:placeholder` - Use descriptive placeholders like [EMAIL]
  - `{:custom, function}` - Custom redaction function

  ## Strategies

  ### Mask Strategy
  Replaces PII with asterisks or custom character:
  ```
  "john@example.com" -> "*****************"
  ```

  ### Partial Strategy
  Shows partial information while hiding sensitive parts:
  ```
  "john@example.com" -> "j***@example.com"
  "555-123-4567" -> "***-***-4567"
  "123-45-6789" -> "***-**-6789"
  ```

  ### Hash Strategy
  Replaces with deterministic hash for anonymization:
  ```
  "john@example.com" -> "HASH_a1b2c3d4"
  ```

  ### Placeholder Strategy
  Uses descriptive type-based placeholders:
  ```
  "john@example.com" -> "[EMAIL]"
  "555-1234" -> "[PHONE]"
  ```

  ## Examples

      # Simple redaction with default mask strategy
      iex> text = "Email: user@example.com"
      iex> PIIRedactor.redact_text(text)
      "Email: *****************"

      # Partial redaction
      iex> entities = PIIScanner.scan("Card: 4532015112830366")
      iex> PIIRedactor.redact("Card: 4532015112830366", entities, strategy: :partial)
      "Card: ************0366"

      # Hash strategy with mapping
      iex> {redacted, mapping} = PIIRedactor.redact_with_mapping(text, entities, strategy: :hash)
      iex> is_map(mapping)
      true
  """

  alias LlmGuard.Detectors.DataLeakage.PIIScanner

  @type redaction_strategy ::
          :mask
          | :partial
          | :hash
          | :placeholder
          | {:custom, (map() -> String.t())}
          | %{optional(atom()) => redaction_strategy()}

  @type redaction_options :: [
          strategy: redaction_strategy(),
          mask_char: String.t(),
          placeholder_format: :square_brackets | :angle_brackets
        ]

  @doc """
  Redacts PII from text based on detected entities.

  ## Parameters

  - `text` - Original text containing PII
  - `entities` - List of PII entities from PIIScanner
  - `opts` - Redaction options

  ## Options

  - `:strategy` - Redaction strategy (default: `:mask`)
  - `:mask_char` - Character for masking (default: `"*"`)
  - `:placeholder_format` - Format for placeholders (default: `:square_brackets`)

  ## Returns

  Redacted text string.
  """
  @spec redact(String.t(), [map()], redaction_options()) :: String.t()
  def redact(text, entities, opts \\ [])

  def redact(text, [], _opts), do: text

  def redact(text, entities, opts) when is_binary(text) and is_list(entities) do
    strategy = Keyword.get(opts, :strategy, :mask)

    # Sort entities by position (reverse order for replacement)
    sorted_entities = Enum.sort_by(entities, & &1.start_pos, :desc)

    # Apply redaction to each entity
    Enum.reduce(sorted_entities, text, fn entity, acc_text ->
      redacted_value = apply_strategy(entity, strategy, opts)

      # Replace the PII in text
      before = String.slice(acc_text, 0, entity.start_pos)
      after_text = String.slice(acc_text, entity.end_pos..-1//1)

      before <> redacted_value <> after_text
    end)
  end

  @doc """
  Scans and redacts PII in one convenient call.

  ## Parameters

  - `text` - Text to scan and redact
  - `opts` - Redaction options (same as `redact/3`)

  ## Returns

  Redacted text string.

  ## Examples

      iex> PIIRedactor.redact_text("Email: user@example.com")
      "Email: *****************"
  """
  @spec redact_text(String.t(), redaction_options()) :: String.t()
  def redact_text(text, opts \\ []) when is_binary(text) do
    entities = PIIScanner.scan(text)
    redact(text, entities, opts)
  end

  @doc """
  Redacts PII and returns both redacted text and a mapping.

  Useful for hash strategy where you want to maintain a lookup table.

  ## Parameters

  - `text` - Original text
  - `entities` - PII entities
  - `opts` - Redaction options

  ## Returns

  Tuple of `{redacted_text, mapping}` where mapping is a map from
  original values to redacted values.

  ## Examples

      {redacted, mapping} = PIIRedactor.redact_with_mapping(text, entities, strategy: :hash)
      # mapping = %{"user@example.com" => "HASH_abc123", ...}
  """
  @spec redact_with_mapping(String.t(), [map()], redaction_options()) ::
          {String.t(), map()}
  def redact_with_mapping(text, entities, opts \\ []) do
    strategy = Keyword.get(opts, :strategy, :hash)
    mapping = %{}

    sorted_entities = Enum.sort_by(entities, & &1.start_pos, :desc)

    {redacted_text, final_mapping} =
      Enum.reduce(sorted_entities, {text, mapping}, fn entity, {acc_text, acc_mapping} ->
        redacted_value = apply_strategy(entity, strategy, opts)

        # Add to mapping
        new_mapping = Map.put(acc_mapping, entity.value, redacted_value)

        # Replace in text
        before = String.slice(acc_text, 0, entity.start_pos)
        after_text = String.slice(acc_text, entity.end_pos..-1//1)

        {before <> redacted_value <> after_text, new_mapping}
      end)

    {redacted_text, final_mapping}
  end

  # Private strategy application functions

  defp apply_strategy(entity, :mask, opts) do
    mask_char = Keyword.get(opts, :mask_char, "*")
    String.duplicate(mask_char, String.length(entity.value))
  end

  defp apply_strategy(entity, :partial, _opts) do
    case entity.type do
      :email -> partial_email(entity.value)
      :phone -> partial_phone(entity.value)
      :ssn -> partial_ssn(entity.value)
      :credit_card -> partial_credit_card(entity.value)
      :ip_address -> partial_ip(entity.value)
      :url -> partial_url(entity.value)
      _ -> String.duplicate("*", String.length(entity.value))
    end
  end

  defp apply_strategy(entity, :hash, _opts) do
    # Create deterministic hash
    hash =
      :crypto.hash(:sha256, entity.value)
      |> Base.encode16(case: :lower)
      |> String.slice(0, 8)

    "HASH_#{hash}"
  end

  defp apply_strategy(entity, :placeholder, opts) do
    format = Keyword.get(opts, :placeholder_format, :square_brackets)

    placeholder_text =
      entity.type
      |> to_string()
      |> String.upcase()

    case format do
      :square_brackets -> "[#{placeholder_text}]"
      :angle_brackets -> "<#{placeholder_text}>"
    end
  end

  defp apply_strategy(entity, {:custom, function}, _opts) when is_function(function, 1) do
    function.(entity)
  end

  defp apply_strategy(entity, strategies, opts) when is_map(strategies) do
    # Mixed strategies per type
    type_strategy = Map.get(strategies, entity.type, :mask)
    apply_strategy(entity, type_strategy, opts)
  end

  # Partial redaction helpers

  defp partial_email(email) do
    case String.split(email, "@") do
      [local, domain] ->
        # Show first character and domain
        first = String.first(local)
        masked_local = first <> String.duplicate("*", String.length(local) - 1)
        masked_local <> "@" <> domain

      _ ->
        String.duplicate("*", String.length(email))
    end
  end

  defp partial_phone(phone) do
    # Extract digits
    digits = String.replace(phone, ~r/\D/, "")

    if String.length(digits) >= 4 do
      # Show last 4 digits
      last_four = String.slice(digits, -4..-1//1)
      mask_length = String.length(phone) - 4

      String.duplicate("*", mask_length) <> last_four
    else
      String.duplicate("*", String.length(phone))
    end
  end

  defp partial_ssn(ssn) do
    case String.split(ssn, "-") do
      [_area, _group, serial] ->
        # Show last 4 digits: ***-**-6789
        "***-**-" <> serial

      _ ->
        # Unformatted: show last 4
        if String.length(ssn) >= 4 do
          String.duplicate("*", String.length(ssn) - 4) <> String.slice(ssn, -4..-1//1)
        else
          String.duplicate("*", String.length(ssn))
        end
    end
  end

  defp partial_credit_card(card) do
    # Show last 4 digits
    digits = String.replace(card, ~r/[-\s]/, "")

    if String.length(digits) >= 4 do
      last_four = String.slice(digits, -4..-1//1)
      String.duplicate("*", String.length(card) - 4) <> last_four
    else
      String.duplicate("*", String.length(card))
    end
  end

  defp partial_ip(ip) do
    # Mask first two octets for IPv4
    case String.split(ip, ".") do
      [_a, _b, c, d] ->
        "***.***." <> c <> "." <> d

      _ ->
        # IPv6 or invalid - full mask
        String.duplicate("*", String.length(ip))
    end
  end

  defp partial_url(url) do
    # Show domain but mask path/query
    case String.split(url, "/", parts: 3) do
      [protocol, domain, _path] ->
        protocol <> "//" <> domain <> "/***"

      _ ->
        String.duplicate("*", String.length(url))
    end
  end
end
