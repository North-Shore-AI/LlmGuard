defmodule LlmGuard.Utils.BrValidationTest do
  use ExUnit.Case, async: true

  alias LlmGuard.Utils.BrValidation

  describe "valid_cpf?/1" do
    test "accepts valid CPFs with and without punctuation" do
      for cpf <- ["123.456.789-09", "11144477735", "529.982.247-25"] do
        assert BrValidation.valid_cpf?(cpf)
      end
    end

    test "rejects bad check digits, wrong length, repeated digits and non-strings" do
      refute BrValidation.valid_cpf?("123.456.789-00")
      refute BrValidation.valid_cpf?("11111111111")
      refute BrValidation.valid_cpf?("123")
      refute BrValidation.valid_cpf?(nil)
    end
  end

  describe "valid_cnpj?/1" do
    test "accepts valid CNPJs with and without punctuation" do
      for cnpj <- ["11.222.333/0001-81", "04.252.011/0001-10", "11222333000181"] do
        assert BrValidation.valid_cnpj?(cnpj)
      end
    end

    test "rejects bad check digits, wrong length and repeated digits" do
      refute BrValidation.valid_cnpj?("11.222.333/0001-82")
      refute BrValidation.valid_cnpj?("00000000000000")
      refute BrValidation.valid_cnpj?("123")
    end
  end

  describe "valid_cep?/1" do
    test "accepts NNNNN-NNN and NNNNNNNN" do
      assert BrValidation.valid_cep?("01310-100")
      assert BrValidation.valid_cep?("01310100")
    end

    test "rejects malformed CEPs" do
      refute BrValidation.valid_cep?("0131-100")
      refute BrValidation.valid_cep?("013101000")
    end
  end

  describe "valid_br_phone?/1" do
    test "accepts mobile and landline, with optional +55" do
      assert BrValidation.valid_br_phone?("(11) 91234-5678")
      assert BrValidation.valid_br_phone?("+55 11 3123-4567")
      assert BrValidation.valid_br_phone?("11912345678")
    end

    test "rejects bad area code, wrong mobile prefix and short numbers" do
      refute BrValidation.valid_br_phone?("(00) 91234-5678")
      refute BrValidation.valid_br_phone?("(11) 81234-5678")
      refute BrValidation.valid_br_phone?("12345")
    end
  end
end
