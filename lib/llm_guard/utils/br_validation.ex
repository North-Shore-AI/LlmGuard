defmodule LlmGuard.Utils.BrValidation do
  @moduledoc """
  Validation for Brazilian identifiers: CPF, CNPJ, CEP and phone numbers.

  CPF and CNPJ are validated by their check digits (dígitos verificadores, mod 11);
  CEP and phone are validated by format. The PII scanner uses these to gate bare-digit
  matches so that arbitrary number runs are not reported as Brazilian PII.
  """

  @cep_regex ~r/^\d{5}-?\d{3}$/

  @doc """
  Validates a CPF (11 digits) by its two check digits. Accepts punctuation
  (`123.456.789-09`) or bare digits. Rejects sequences of a single repeated digit.
  """
  @spec valid_cpf?(String.t()) :: boolean()
  def valid_cpf?(value) when is_binary(value),
    do: valid_document?(value, 9, [10, 9, 8, 7, 6, 5, 4, 3, 2])

  def valid_cpf?(_), do: false

  @doc """
  Validates a CNPJ (14 digits) by its two check digits. Accepts punctuation
  (`11.222.333/0001-81`) or bare digits. Numeric CNPJ only.
  """
  @spec valid_cnpj?(String.t()) :: boolean()
  def valid_cnpj?(value) when is_binary(value),
    do: valid_document?(value, 12, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])

  def valid_cnpj?(_), do: false

  @doc "Validates a CEP by format (`NNNNN-NNN` or `NNNNNNNN`)."
  @spec valid_cep?(String.t()) :: boolean()
  def valid_cep?(value) when is_binary(value), do: String.match?(value, @cep_regex)
  def valid_cep?(_), do: false

  @doc """
  Validates a Brazilian phone number: optional `+55`, a 2-digit area code (DDD 11–99),
  then a 9-digit mobile (leading `9`) or 8-digit landline (leading 2–5).
  """
  @spec valid_br_phone?(String.t()) :: boolean()
  def valid_br_phone?(value) when is_binary(value) do
    case String.replace(value, ~r/\D/, "") do
      "55" <> rest when byte_size(rest) in [10, 11] -> valid_local_phone?(rest)
      local when byte_size(local) in [10, 11] -> valid_local_phone?(local)
      _ -> false
    end
  end

  def valid_br_phone?(_), do: false

  # Private helpers

  defp to_int_list(value) do
    value
    |> String.replace(~r/\D/, "")
    |> String.graphemes()
    |> Enum.map(&String.to_integer/1)
  end

  # Length is the body plus its two check digits; an all-same-digit run is invalid.
  defp valid_document?(value, body_len, weights) do
    digits = to_int_list(value)

    length(digits) == body_len + 2 and not repeated?(digits) and
      check_digits_valid?(digits, body_len, weights)
  end

  # Second check digit reuses the first weights prefixed by `hd(weights) + 1`.
  defp check_digits_valid?(digits, body_len, weights) do
    {body, [c1, c2]} = Enum.split(digits, body_len)
    d1 = check_digit(body, weights)
    d2 = check_digit(body ++ [d1], [hd(weights) + 1 | weights])
    c1 == d1 and c2 == d2
  end

  defp check_digit(digits, weights) do
    sum =
      digits
      |> Enum.zip(weights)
      |> Enum.reduce(0, fn {digit, weight}, acc -> acc + digit * weight end)

    case rem(sum, 11) do
      remainder when remainder < 2 -> 0
      remainder -> 11 - remainder
    end
  end

  defp repeated?([]), do: false
  defp repeated?([head | tail]), do: Enum.all?(tail, &(&1 == head))

  defp valid_local_phone?(local) do
    {ddd, number} = String.split_at(local, 2)

    String.to_integer(ddd) in 11..99 and
      case String.length(number) do
        9 -> String.starts_with?(number, "9")
        8 -> String.first(number) in ~w(2 3 4 5)
        _ -> false
      end
  end
end
