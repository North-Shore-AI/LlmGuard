defmodule LlmGuard.Locales do
  @moduledoc """
  Registry of locale packs.

  Adding a language is two steps: implement `LlmGuard.Locale` in a new module and add one
  entry to `@registry`. Detectors and config then support it with no further changes.

  `:en` is the always-on base provided directly by the detectors, so it is not a registered
  pack; registered packs contribute additively on top of it.
  """

  alias LlmGuard.Locales.PtBr

  @registry %{pt_br: PtBr}

  @doc "Languages accepted by `Config` `:languages`: the `:en` base plus every registered pack."
  @spec supported() :: [atom()]
  def supported, do: [:en | Map.keys(@registry)]

  @doc "Injection patterns contributed by the enabled locale packs."
  @spec injection_patterns([atom()]) :: [map()]
  def injection_patterns(languages), do: gather(languages, & &1.injection_patterns())

  @doc "Jailbreak patterns (category => regexes) merged across the enabled locale packs."
  @spec jailbreak_patterns([atom()]) :: %{atom() => [Regex.t()]}
  def jailbreak_patterns(languages) do
    languages
    |> packs()
    |> Enum.reduce(%{}, fn pack, acc ->
      Map.merge(acc, pack.jailbreak_patterns(), fn _category, a, b -> a ++ b end)
    end)
  end

  @doc "Region PII specs contributed by the enabled locale packs."
  @spec pii_specs([atom()]) :: [LlmGuard.Locale.pii_spec()]
  def pii_specs(languages), do: gather(languages, & &1.pii_specs())

  @doc "Looks up a PII spec by type across all packs, since `scan_by_type/2` takes no language."
  @spec pii_spec(atom()) :: LlmGuard.Locale.pii_spec() | nil
  def pii_spec(type) do
    @registry
    |> Map.values()
    |> Enum.flat_map(& &1.pii_specs())
    |> Enum.find(&(&1.type == type))
  end

  defp gather(languages, fun), do: languages |> packs() |> Enum.flat_map(fun)

  defp packs(languages) do
    languages
    |> Enum.uniq()
    |> Enum.flat_map(fn language ->
      case Map.fetch(@registry, language) do
        {:ok, pack} -> [pack]
        :error -> []
      end
    end)
  end
end
