defmodule LlmGuard.Detectors.DataLeakage.PIIScannerTest do
  @moduledoc """
  Tests for PII (Personally Identifiable Information) scanner.

  Tests comprehensive detection of:
  - Email addresses
  - Phone numbers (US and international)
  - Social Security Numbers (SSN)
  - Credit card numbers
  - IP addresses
  - Physical addresses
  - Names (with context)
  """
  use ExUnit.Case, async: true

  alias LlmGuard.Detectors.DataLeakage.PIIScanner

  describe "scan/1" do
    test "returns empty list for text without PII" do
      text = "The weather is nice today. I enjoy walking in the park."
      assert PIIScanner.scan(text) == []
    end

    test "returns detected entities with types" do
      text = "Contact me at john@example.com or call 555-123-4567"
      entities = PIIScanner.scan(text)

      assert length(entities) == 2
      assert Enum.any?(entities, &(&1.type == :email))
      assert Enum.any?(entities, &(&1.type == :phone))
    end
  end

  describe "email detection" do
    test "detects standard email addresses" do
      emails = [
        "user@example.com",
        "john.doe@company.co.uk",
        "test+tag@domain.org",
        "name_123@sub.domain.com"
      ]

      for email <- emails do
        text = "Email: #{email}"
        entities = PIIScanner.scan(text)

        assert length(entities) >= 1
        entity = Enum.find(entities, &(&1.type == :email))
        assert entity != nil
        assert entity.value == email
        assert entity.confidence >= 0.9
      end
    end

    test "detects multiple emails in text" do
      text = "Contact john@example.com or jane@test.org for assistance"
      entities = PIIScanner.scan(text)

      emails = Enum.filter(entities, &(&1.type == :email))
      assert length(emails) == 2
    end

    test "does not detect invalid email-like strings" do
      invalid = [
        "not.an.email",
        "@missing.user.com",
        "no.domain@",
        "user@",
        "@domain.com"
      ]

      for text <- invalid do
        entities = PIIScanner.scan(text)
        emails = Enum.filter(entities, &(&1.type == :email))
        assert length(emails) == 0
      end
    end
  end

  describe "phone number detection" do
    test "detects US phone numbers in various formats" do
      phones = [
        "555-123-4567",
        "(555) 123-4567",
        "555.123.4567",
        "5551234567",
        "+1-555-123-4567",
        "1 (555) 123-4567"
      ]

      for phone <- phones do
        text = "Call #{phone} for info"
        entities = PIIScanner.scan(text)

        phone_entities = Enum.filter(entities, &(&1.type == :phone))
        assert length(phone_entities) >= 1, "Failed to detect: #{phone}"
      end
    end

    test "detects international phone numbers" do
      phones = [
        "+44 20 7946 0958",
        "+33 1 42 86 82 00",
        "+81 3-1234-5678"
      ]

      for phone <- phones do
        text = "International: #{phone}"
        entities = PIIScanner.scan(text)

        phone_entities = Enum.filter(entities, &(&1.type == :phone))
        assert length(phone_entities) >= 1
      end
    end

    test "includes position information" do
      text = "Call me at 555-123-4567 today"
      entities = PIIScanner.scan(text)

      phone = Enum.find(entities, &(&1.type == :phone))
      assert phone.start_pos > 0
      assert phone.end_pos > phone.start_pos
    end
  end

  describe "SSN detection" do
    test "detects SSN in standard format" do
      ssns = [
        "123-45-6789",
        "987-65-4321"
      ]

      for ssn <- ssns do
        text = "SSN: #{ssn}"
        entities = PIIScanner.scan(text)

        ssn_entities = Enum.filter(entities, &(&1.type == :ssn))
        assert length(ssn_entities) == 1
        assert hd(ssn_entities).value == ssn
        assert hd(ssn_entities).confidence >= 0.95
      end
    end

    test "detects SSN without dashes" do
      text = "SSN 123456789"
      entities = PIIScanner.scan(text)

      ssn_entities = Enum.filter(entities, &(&1.type == :ssn))
      assert length(ssn_entities) == 1
    end

    test "does not detect invalid SSN patterns" do
      invalid = [
        # Invalid SSN
        "000-00-0000",
        # Invalid group
        "123-00-0000",
        # Invalid serial
        "123-45-0000"
      ]

      for ssn <- invalid do
        text = "Number: #{ssn}"
        entities = PIIScanner.scan(text)

        ssn_entities = Enum.filter(entities, &(&1.type == :ssn))
        assert length(ssn_entities) == 0
      end
    end
  end

  describe "credit card detection" do
    test "detects major credit card formats" do
      cards = [
        # Visa
        "4532015112830366",
        # Mastercard
        "5425233430109903",
        # Amex
        "374245455400126",
        # Discover
        "6011111111111117"
      ]

      for card <- cards do
        text = "Card: #{card}"
        entities = PIIScanner.scan(text)

        cc_entities = Enum.filter(entities, &(&1.type == :credit_card))
        assert length(cc_entities) == 1, "Failed to detect: #{card}"
      end
    end

    test "detects credit cards with spaces or dashes" do
      cards = [
        "4532 0151 1283 0366",
        "5425-2334-3010-9903"
      ]

      for card <- cards do
        text = "Payment: #{card}"
        entities = PIIScanner.scan(text)

        cc_entities = Enum.filter(entities, &(&1.type == :credit_card))
        assert length(cc_entities) >= 1
      end
    end

    test "validates with Luhn algorithm" do
      # Invalid Luhn checksum
      invalid_card = "4532015112830367"
      text = "Card: #{invalid_card}"
      entities = PIIScanner.scan(text)

      cc_entities = Enum.filter(entities, &(&1.type == :credit_card))
      # Should not detect or have low confidence
      if length(cc_entities) > 0 do
        assert hd(cc_entities).confidence < 0.7
      end
    end
  end

  describe "IP address detection" do
    test "detects IPv4 addresses" do
      ips = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.254.1",
        "8.8.8.8"
      ]

      for ip <- ips do
        text = "Server IP: #{ip}"
        entities = PIIScanner.scan(text)

        ip_entities = Enum.filter(entities, &(&1.type == :ip_address))
        assert length(ip_entities) == 1
        assert hd(ip_entities).value == ip
      end
    end

    test "detects IPv6 addresses" do
      ips = [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::8a2e:370:7334",
        "::1"
      ]

      for ip <- ips do
        text = "IPv6: #{ip}"
        entities = PIIScanner.scan(text)

        ip_entities = Enum.filter(entities, &(&1.type == :ip_address))
        assert length(ip_entities) >= 1
      end
    end

    test "does not detect invalid IP addresses" do
      invalid = [
        "256.256.256.256",
        "192.168.1",
        "999.999.999.999"
      ]

      for ip <- invalid do
        text = "Address: #{ip}"
        entities = PIIScanner.scan(text)

        ip_entities = Enum.filter(entities, &(&1.type == :ip_address))
        assert length(ip_entities) == 0
      end
    end
  end

  describe "URL detection" do
    test "detects URLs that may contain sensitive paths" do
      urls = [
        "https://example.com/user/12345/profile",
        "http://api.example.com/v1/users?id=abc123",
        "https://example.com/reset-password?token=secret123"
      ]

      for url <- urls do
        text = "Visit #{url}"
        entities = PIIScanner.scan(text)

        url_entities = Enum.filter(entities, &(&1.type == :url))
        assert length(url_entities) >= 1
      end
    end
  end

  describe "comprehensive scanning" do
    test "detects multiple PII types in complex text" do
      text = """
      Contact Information:
      Email: john.doe@company.com
      Phone: (555) 123-4567
      SSN: 123-45-6789
      Credit Card: 4532-0151-1283-0366
      IP: 192.168.1.100
      """

      entities = PIIScanner.scan(text)

      # Should detect all types
      types = Enum.map(entities, & &1.type) |> Enum.uniq()

      assert :email in types
      assert :phone in types
      assert :ssn in types
      assert :credit_card in types
      assert :ip_address in types

      # Should have at least 5 entities
      assert length(entities) >= 5
    end

    test "entities include all required fields" do
      text = "Email me at test@example.com"
      entities = PIIScanner.scan(text)

      assert length(entities) == 1
      entity = hd(entities)

      # Required fields
      assert Map.has_key?(entity, :type)
      assert Map.has_key?(entity, :value)
      assert Map.has_key?(entity, :confidence)
      assert Map.has_key?(entity, :start_pos)
      assert Map.has_key?(entity, :end_pos)

      # Type checks
      assert is_atom(entity.type)
      assert is_binary(entity.value)
      assert is_float(entity.confidence)
      assert entity.confidence >= 0.0 and entity.confidence <= 1.0
      assert is_integer(entity.start_pos)
      assert is_integer(entity.end_pos)
    end
  end

  describe "edge cases" do
    test "handles empty string" do
      assert PIIScanner.scan("") == []
    end

    test "handles very long text" do
      long_text = String.duplicate("word ", 10_000) <> "Email: test@example.com"
      entities = PIIScanner.scan(long_text)

      assert length(entities) == 1
    end

    test "handles unicode text" do
      text = "Email в тексте: user@example.com 中文"
      entities = PIIScanner.scan(text)

      assert length(entities) == 1
      assert hd(entities).type == :email
    end

    test "handles text with no spaces" do
      text = "EmailAddressIsuser@example.comWithNoSpaces"
      entities = PIIScanner.scan(text)

      emails = Enum.filter(entities, &(&1.type == :email))
      assert length(emails) == 1
    end
  end

  describe "scan_by_type/2" do
    test "scans for specific PII type only" do
      text = "Email: test@example.com Phone: 555-1234"

      email_entities = PIIScanner.scan_by_type(text, :email)
      phone_entities = PIIScanner.scan_by_type(text, :phone)

      assert length(email_entities) == 1
      assert hd(email_entities).type == :email

      assert length(phone_entities) == 1
      assert hd(phone_entities).type == :phone
    end

    test "returns empty for type not present" do
      text = "Just normal text here"
      entities = PIIScanner.scan_by_type(text, :ssn)

      assert entities == []
    end
  end

  describe "contains_pii?/1" do
    test "returns true if any PII found" do
      text = "Contact: user@example.com"
      assert PIIScanner.contains_pii?(text) == true
    end

    test "returns false if no PII found" do
      text = "Just a normal sentence."
      assert PIIScanner.contains_pii?(text) == false
    end
  end
end
