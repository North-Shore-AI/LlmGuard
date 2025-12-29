defmodule LlmGuard.MixProject do
  use Mix.Project

  @version "0.3.1"
  @source_url "https://github.com/North-Shore-AI/LlmGuard"

  def project do
    [
      app: :llm_guard,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,
      name: "LlmGuard",

      # Testing
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        dialyzer: :test,
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],

      # Dialyzer
      dialyzer: [
        plt_add_apps: [:ex_unit],
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
        flags: [:error_handling, :underspecs, :unmatched_returns]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      # CrucibleIR integration
      {:crucible_ir, "~> 0.2.1"},

      # Documentation
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},

      # Testing
      {:stream_data, "~> 1.0", only: [:test, :dev]},
      {:mox, "~> 1.0", only: :test},
      {:supertester, "~> 0.4.0", only: :test},

      # Code quality
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test},

      # Performance
      {:benchee, "~> 1.1", only: :dev},

      # Telemetry
      {:telemetry, "~> 1.2"},
      {:telemetry_metrics, "~> 0.6"}
    ]
  end

  defp description do
    "AI Firewall and guardrails for LLM-based Elixir applications. Provides prompt injection detection, data leakage prevention, jailbreak detection, and comprehensive security guardrails."
  end

  defp package do
    [
      name: "llm_guard",
      description: description(),
      files:
        ~w(lib mix.exs README.md CHANGELOG.md LICENSE IMPLEMENTATION_STATUS.md docs examples),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Online documentation" => "https://hexdocs.pm/llm_guard"
      },
      maintainers: ["nshkrdotcom"]
    ]
  end

  defp docs do
    [
      main: "readme",
      name: "LlmGuard",
      source_ref: "v#{@version}",
      source_url: @source_url,
      homepage_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "IMPLEMENTATION_STATUS.md",
        "docs/architecture.md",
        "docs/threat_model.md",
        "docs/guardrails.md",
        "docs/roadmap.md",
        "docs/test_fine_tuning_guide.md",
        "docs/jailbreak_detector_implementation.md"
      ],
      groups_for_extras: [
        "Project Status": [
          "IMPLEMENTATION_STATUS.md"
        ],
        "Architecture & Design": [
          "docs/architecture.md",
          "docs/threat_model.md",
          "docs/guardrails.md"
        ],
        "Implementation Guides": [
          "docs/test_fine_tuning_guide.md",
          "docs/jailbreak_detector_implementation.md",
          "docs/roadmap.md"
        ]
      ],
      assets: %{"assets" => "assets"},
      logo: "assets/LlmGuard.svg",
      before_closing_head_tag: &mermaid_config/1
    ]
  end

  defp mermaid_config(:html) do
    """
    <script defer src="https://cdn.jsdelivr.net/npm/mermaid@10.2.3/dist/mermaid.min.js"></script>
    <script>
      let initialized = false;

      window.addEventListener("exdoc:loaded", () => {
        if (!initialized) {
          mermaid.initialize({
            startOnLoad: false,
            theme: document.body.className.includes("dark") ? "dark" : "default"
          });
          initialized = true;
        }

        let id = 0;
        for (const codeEl of document.querySelectorAll("pre code.mermaid")) {
          const preEl = codeEl.parentElement;
          const graphDefinition = codeEl.textContent;
          const graphEl = document.createElement("div");
          const graphId = "mermaid-graph-" + id++;
          mermaid.render(graphId, graphDefinition).then(({svg, bindFunctions}) => {
            graphEl.innerHTML = svg;
            bindFunctions?.(graphEl);
            preEl.insertAdjacentElement("afterend", graphEl);
            preEl.remove();
          });
        }
      });
    </script>
    """
  end

  defp mermaid_config(_), do: ""
end
