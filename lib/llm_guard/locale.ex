defmodule LlmGuard.Locale do
  @moduledoc """
  Behaviour for a locale pack: the language patterns and region PII that activate when the
  locale is enabled via `LlmGuard.Config` `:languages`.

  Each callback defaults to empty, so a pack implements only what it provides.
  """

  @type pii_spec :: %{
          type: atom(),
          regex: Regex.t(),
          validate: (String.t() -> boolean()),
          confidence: float()
        }

  @callback injection_patterns() :: [map()]
  @callback jailbreak_patterns() :: %{atom() => [Regex.t()]}
  @callback pii_specs() :: [pii_spec()]

  defmacro __using__(_opts) do
    quote do
      @behaviour LlmGuard.Locale

      @impl true
      def injection_patterns, do: []

      @impl true
      def jailbreak_patterns, do: %{}

      @impl true
      def pii_specs, do: []

      defoverridable injection_patterns: 0, jailbreak_patterns: 0, pii_specs: 0
    end
  end
end
