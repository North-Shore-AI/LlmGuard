defmodule LlmGuard.Detectors.DataLeakageTest do
  @moduledoc """
  Tests for DataLeakage detector integrating PII scanner and redactor.
  """
  use ExUnit.Case, async: true

  alias LlmGuard.Detectors.DataLeakage

  describe "detector interface" do
    test "implements detector behaviour" do
      assert function_exported?(DataLeakage, :detect, 2)
      assert function_exported?(DataLeakage, :name, 0)
      assert function_exported?(DataLeakage, :description, 0)
    end

    test "name returns identifier" do
      assert DataLeakage.name() == "data_leakage"
    end

    test "description returns human-readable text" do
      description = DataLeakage.description()
      assert is_binary(description)
      assert String.length(description) > 10
    end
  end

  describe "detect/2 with PII detection" do
    test "detects email addresses" do
      input = "Contact me at john@example.com"

      assert {:detected, result} = DataLeakage.detect(input, [])

      assert result.confidence > 0.8
      assert result.category == :pii_leakage
      assert length(result.patterns_matched) > 0
      assert "email" in result.patterns_matched or :email in result.patterns_matched
    end

    test "detects multiple PII types" do
      input = "Email: john@example.com Phone: 555-123-4567 SSN: 123-45-6789"

      assert {:detected, result} = DataLeakage.detect(input, [])

      # Should detect multiple types
      assert length(result.patterns_matched) >= 2
      assert result.confidence >= 0.9
    end

    test "returns safe for text without PII" do
      input = "The weather is nice today"

      assert {:safe, result} = DataLeakage.detect(input, [])
      assert is_map(result)
    end
  end

  describe "detect/2 with redaction" do
    test "includes redacted text in metadata when enabled" do
      input = "Email: test@example.com"

      {:detected, result} = DataLeakage.detect(input, redact: true)

      assert Map.has_key?(result.metadata, :redacted_text)
      refute String.contains?(result.metadata.redacted_text, "test@example.com")
    end

    test "uses specified redaction strategy" do
      input = "Email: test@example.com"

      {:detected, result} = DataLeakage.detect(input, redact: true, redaction_strategy: :partial)

      redacted = result.metadata.redacted_text
      # Partial strategy should keep domain
      assert String.contains?(redacted, "@example.com")
    end

    test "does not redact when redact option is false" do
      input = "Email: test@example.com"

      {:detected, result} = DataLeakage.detect(input, redact: false)

      # Should not have redacted text in metadata
      refute Map.has_key?(result.metadata, :redacted_text)
    end
  end

  describe "detect/2 confidence scoring" do
    test "higher confidence for multiple PII instances" do
      single_pii = "Email: test@example.com"
      multiple_pii = "Email: test@example.com Phone: 555-1234 SSN: 123-45-6789"

      {:detected, result1} = DataLeakage.detect(single_pii, [])
      {:detected, result2} = DataLeakage.detect(multiple_pii, [])

      assert result2.confidence >= result1.confidence
    end

    test "confidence threshold filtering" do
      input = "Email: test@example.com"

      # With very high threshold, might not detect low-confidence PII
      _result_high = DataLeakage.detect(input, confidence_threshold: 0.99)

      # With normal threshold, should detect
      result_normal = DataLeakage.detect(input, confidence_threshold: 0.7)

      # Both should work for high-confidence email detection
      assert {:detected, _} = result_normal
    end
  end

  describe "detect/2 with PII type filtering" do
    test "can filter specific PII types to detect" do
      input = "Email: test@example.com Phone: 555-1234"

      # Only detect emails
      {:detected, result} = DataLeakage.detect(input, pii_types: [:email])

      # Should only match email
      assert :email in result.patterns_matched or "email" in result.patterns_matched
    end

    test "detects all types when no filter specified" do
      input = "Email: test@example.com Phone: 555-123-4567"

      {:detected, result} = DataLeakage.detect(input, [])

      # Should detect both
      assert length(result.patterns_matched) >= 1
    end
  end

  describe "metadata information" do
    test "includes detected PII count" do
      input = "Email: a@test.com and b@test.com"

      {:detected, result} = DataLeakage.detect(input, [])

      assert Map.has_key?(result.metadata, :pii_count)
      assert result.metadata.pii_count >= 2
    end

    test "includes PII types found" do
      input = "Email: test@example.com Phone: 555-1234"

      {:detected, result} = DataLeakage.detect(input, [])

      assert Map.has_key?(result.metadata, :pii_types)
      assert is_list(result.metadata.pii_types)
    end

    test "includes entity details" do
      input = "Email: test@example.com"

      {:detected, result} = DataLeakage.detect(input, [])

      assert Map.has_key?(result.metadata, :entities)
      assert is_list(result.metadata.entities)
      assert length(result.metadata.entities) > 0
    end
  end

  describe "edge cases" do
    test "handles empty input" do
      assert {:safe, _} = DataLeakage.detect("", [])
    end

    test "handles very long input" do
      long_text = String.duplicate("word ", 1000) <> " email: test@example.com"

      assert {:detected, _} = DataLeakage.detect(long_text, [])
    end

    test "handles unicode text" do
      input = "Email в тексте: user@example.com 中文"

      assert {:detected, result} = DataLeakage.detect(input, [])
      assert result.confidence > 0.8
    end
  end

  describe "integration with pipeline" do
    test "can be used in security pipeline" do
      # Ensure it has the right return format for pipeline
      {:detected, result} = DataLeakage.detect("Email: test@example.com", [])

      assert is_float(result.confidence)
      assert is_atom(result.category)
      assert is_list(result.patterns_matched)
      assert is_map(result.metadata)
    end
  end

  describe "disabled state" do
    test "can be disabled via options" do
      input = "Email: test@example.com"

      assert {:safe, result} = DataLeakage.detect(input, enabled: false)
      assert result.enabled == false
    end
  end
end
