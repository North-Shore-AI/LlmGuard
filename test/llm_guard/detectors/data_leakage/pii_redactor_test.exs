defmodule LlmGuard.Detectors.DataLeakage.PIIRedactorTest do
  @moduledoc """
  Tests for PII redaction with multiple strategies.

  Tests cover:
  - Mask strategy (replace with asterisks)
  - Hash strategy (one-way hash for anonymization)
  - Partial strategy (show partial info)
  - Placeholder strategy (descriptive replacement)
  - Custom strategy support
  """
  use ExUnit.Case, async: true

  alias LlmGuard.Detectors.DataLeakage.{PIIRedactor, PIIScanner}

  describe "redact/2 with mask strategy" do
    test "masks email addresses" do
      text = "Contact me at john@example.com"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :mask)

      assert result == "Contact me at *****************"
    end

    test "masks multiple PII types" do
      text = "Email: john@example.com Phone: 555-1234"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :mask)

      refute String.contains?(result, "john@example.com")
      refute String.contains?(result, "555-1234")
      assert String.contains?(result, "*")
    end

    test "preserves text structure" do
      text = "Call 555-123-4567 or email user@example.com today"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :mask)

      # Should maintain sentence structure
      assert String.starts_with?(result, "Call ")
      assert String.contains?(result, " or email ")
      assert String.ends_with?(result, " today")
    end
  end

  describe "redact/2 with partial strategy" do
    test "shows partial email (keeps domain)" do
      text = "Email: john.doe@company.com"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :partial)

      # Should show j***@company.com or similar
      assert String.contains?(result, "@company.com")
      refute String.contains?(result, "john.doe")
    end

    test "shows partial phone number (last 4 digits)" do
      text = "Call 555-123-4567"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :partial)

      # Should show ***-***-4567 or similar
      assert String.contains?(result, "4567")
      refute String.contains?(result, "555-123")
    end

    test "shows partial SSN (last 4 digits)" do
      text = "SSN: 123-45-6789"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :partial)

      # Should show ***-**-6789
      assert String.contains?(result, "6789")
      refute String.contains?(result, "123-45")
    end

    test "shows partial credit card (last 4 digits)" do
      text = "Card: 4532015112830366"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :partial)

      # Should show ************0366
      assert String.contains?(result, "0366")
      refute String.contains?(result, "4532015112")
    end
  end

  describe "redact/2 with hash strategy" do
    test "replaces with consistent hash" do
      text = "Email: test@example.com"
      entities = PIIScanner.scan(text)

      result1 = PIIRedactor.redact(text, entities, strategy: :hash)
      result2 = PIIRedactor.redact(text, entities, strategy: :hash)

      # Same input should produce same hash
      assert result1 == result2
      refute String.contains?(result1, "test@example.com")
    end

    test "different PIIs produce different hashes" do
      text1 = "Email: user1@example.com"
      text2 = "Email: user2@example.com"

      entities1 = PIIScanner.scan(text1)
      entities2 = PIIScanner.scan(text2)

      result1 = PIIRedactor.redact(text1, entities1, strategy: :hash)
      result2 = PIIRedactor.redact(text2, entities2, strategy: :hash)

      assert result1 != result2
    end

    test "hash is deterministic and repeatable" do
      text = "Phone: 555-123-4567"
      entities = PIIScanner.scan(text)

      results =
        for _ <- 1..5 do
          PIIRedactor.redact(text, entities, strategy: :hash)
        end

      # All should be identical
      assert Enum.uniq(results) |> length() == 1
    end
  end

  describe "redact/2 with placeholder strategy" do
    test "uses descriptive placeholders" do
      text = "Email: john@example.com Phone: 555-1234"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :placeholder)

      assert String.contains?(result, "[EMAIL]") or String.contains?(result, "<EMAIL>")
      assert String.contains?(result, "[PHONE]") or String.contains?(result, "<PHONE>")
      refute String.contains?(result, "john@example.com")
    end

    test "uses correct placeholder for each PII type" do
      text = """
      Email: user@example.com
      Phone: 555-1234
      SSN: 123-45-6789
      Card: 4532015112830366
      IP: 192.168.1.1
      """

      entities = PIIScanner.scan(text)
      result = PIIRedactor.redact(text, entities, strategy: :placeholder)

      # Should contain type-specific placeholders
      assert String.match?(result, ~r/\[(EMAIL|PHONE|SSN|CREDIT_CARD|IP_ADDRESS)\]/i) or
               String.match?(result, ~r/<(EMAIL|PHONE|SSN|CREDIT_CARD|IP_ADDRESS)>/i)
    end
  end

  describe "redact/2 with custom strategy" do
    test "supports custom redaction function" do
      text = "Email: test@example.com"
      entities = PIIScanner.scan(text)

      custom_fn = fn _entity -> "[REDACTED]" end

      result = PIIRedactor.redact(text, entities, strategy: {:custom, custom_fn})

      assert result == "Email: [REDACTED]"
    end

    test "custom function receives entity details" do
      text = "Email: test@example.com"
      entities = PIIScanner.scan(text)

      custom_fn = fn entity ->
        "[#{String.upcase(to_string(entity.type))}:#{entity.confidence}]"
      end

      result = PIIRedactor.redact(text, entities, strategy: {:custom, custom_fn})

      assert String.contains?(result, "[EMAIL:")
      assert String.contains?(result, "0.95]")
    end
  end

  describe "redact/2 with mixed strategies" do
    test "applies different strategies to different PII types" do
      text = "Email: john@example.com Phone: 555-1234"
      entities = PIIScanner.scan(text)

      strategies = %{
        email: :partial,
        phone: :mask
      }

      result = PIIRedactor.redact(text, entities, strategy: strategies)

      # Email should be partial (showing domain)
      assert String.contains?(result, "@example.com")
      # Phone should be fully masked
      assert String.match?(result, ~r/\*{3,}/) or String.match?(result, ~r/\#{3,}/)
    end
  end

  describe "redact/2 edge cases" do
    test "handles empty entity list" do
      text = "No PII here"
      entities = []

      result = PIIRedactor.redact(text, entities, strategy: :mask)

      assert result == text
    end

    test "handles empty text" do
      result = PIIRedactor.redact("", [], strategy: :mask)
      assert result == ""
    end

    test "handles overlapping entities gracefully" do
      # In case scanner returns overlapping matches
      text = "test@example.com"

      entities = [
        %{type: :email, value: "test@example.com", start_pos: 0, end_pos: 16},
        %{type: :url, value: "example.com", start_pos: 5, end_pos: 16}
      ]

      result = PIIRedactor.redact(text, entities, strategy: :mask)

      # Should handle without crashing
      assert is_binary(result)
    end

    test "preserves unicode characters" do
      text = "Email в тексте: user@example.com 中文"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :mask)

      assert String.contains?(result, "Email в тексте:")
      assert String.contains?(result, "中文")
    end
  end

  describe "redact_text/2 convenience function" do
    test "scans and redacts in one call" do
      text = "Contact john@example.com or 555-1234"

      result = PIIRedactor.redact_text(text, strategy: :mask)

      refute String.contains?(result, "john@example.com")
      refute String.contains?(result, "555-1234")
    end

    test "uses default mask strategy if not specified" do
      text = "Email: user@example.com"

      result = PIIRedactor.redact_text(text)

      refute String.contains?(result, "user@example.com")
      assert String.contains?(result, "*")
    end
  end

  describe "configuration options" do
    test "respects mask_char option" do
      text = "Email: test@example.com"
      entities = PIIScanner.scan(text)

      result = PIIRedactor.redact(text, entities, strategy: :mask, mask_char: "#")

      assert String.contains?(result, "#")
      refute String.contains?(result, "*")
    end

    test "respects placeholder_format option" do
      text = "Email: test@example.com"
      entities = PIIScanner.scan(text)

      result =
        PIIRedactor.redact(text, entities,
          strategy: :placeholder,
          placeholder_format: :angle_brackets
        )

      assert String.contains?(result, "<EMAIL>")
    end
  end

  describe "reversibility" do
    test "hash strategy allows lookup mapping" do
      text = "Contact user1@example.com and user2@example.com"
      entities = PIIScanner.scan(text)

      {result, mapping} = PIIRedactor.redact_with_mapping(text, entities, strategy: :hash)

      # Mapping should contain original -> hash pairs
      assert is_map(mapping)
      assert map_size(mapping) == 2
      refute String.contains?(result, "user1@example.com")
    end
  end
end
