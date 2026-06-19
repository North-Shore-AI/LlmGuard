defmodule LlmGuard.Detectors.DataLeakage.PIIScannerBrTest do
  use ExUnit.Case, async: true

  alias LlmGuard.Detectors.DataLeakage.PIIRedactor
  alias LlmGuard.Detectors.DataLeakage.PIIScanner

  @sample "Cliente CPF 529.982.247-25, CNPJ 11.222.333/0001-81, CEP 01310-100, tel (11) 91234-5678"

  describe "scan/2 with [:pt_br]" do
    test "detects CPF, CNPJ, CEP and Brazilian phone" do
      types = @sample |> PIIScanner.scan([:pt_br]) |> Enum.map(& &1.type)

      for expected <- [:cpf, :cnpj, :cep, :br_phone] do
        assert expected in types
      end
    end

    test "detects PII when accented characters precede the match (byte-offset safe)" do
      types =
        PIIScanner.scan("O CPF do cliente é 529.982.247-25", [:pt_br]) |> Enum.map(& &1.type)

      assert :cpf in types
    end

    test "redaction stays aligned when accented characters precede the match" do
      text = "O CPF do cliente é 529.982.247-25, confirma?"
      redacted = PIIRedactor.redact(text, PIIScanner.scan(text, [:pt_br]), strategy: :placeholder)
      assert redacted == "O CPF do cliente é [CPF], confirma?"
    end

    test "does not report invalid CPF/CNPJ (check-digit gated)" do
      assert PIIScanner.scan("CPF 123.456.789-00", [:pt_br]) == []
      assert PIIScanner.scan("CNPJ 11.222.333/0001-82", [:pt_br]) == []
    end
  end

  describe "gating and backward compatibility" do
    test "Brazilian PII is not reported when pt_br is not enabled" do
      types = PIIScanner.scan(@sample, [:en]) |> Enum.map(& &1.type)
      refute Enum.any?(types, &(&1 in [:cpf, :cnpj, :cep, :br_phone]))
    end

    test "scan/1 keeps the original English-only behavior" do
      assert PIIScanner.scan("Email: user@example.com") |> hd() |> Map.get(:type) == :email
    end
  end
end
