defmodule LlmGuard.Locales.PtBr do
  @moduledoc """
  Brazilian-Portuguese locale pack: PT injection and jailbreak patterns plus Brazilian PII
  (CPF, CNPJ, CEP, phone). Regexes use the `u` flag so multibyte accent classes match, and
  tolerate missing accents (e.g. instrucoes/instruções) since users often type without them.
  """

  use LlmGuard.Locale

  alias LlmGuard.Utils.BrValidation

  @impl true
  def injection_patterns do
    [
      # Instruction Override
      %{
        regex:
          ~r/(ignore|ignora|desconsidere|esque[çc]a|esque[çc]e)\s+(todas\s+as\s+|as\s+)?(instru[çc][õo]es|regras|ordens|comandos|diretrizes)\s+(anteriores|acima|pr[ée]vias)/iu,
        name: "ignore_previous_instructions_pt",
        severity: :high,
        category: :instruction_override,
        confidence: 0.95
      },
      %{
        regex:
          ~r/(ignore|ignora|desconsidere|esque[çc]a)\s+(todas\s+as\s+|as\s+)?(instru[çc][õo]es|regras|filtros|seguran[çc]a)/iu,
        name: "ignore_instructions_pt",
        severity: :medium,
        category: :instruction_override,
        confidence: 0.82
      },
      %{
        regex: ~r/(esque[çc]a|ignore)\s+tudo\s+(acima|anterior|antes)/iu,
        name: "forget_everything_above_pt",
        severity: :high,
        category: :instruction_override,
        confidence: 0.9
      },
      %{
        regex:
          ~r/(contorne|burle|ignore)\s+(toda\s+a\s+|a\s+|todas\s+as\s+)?(seguran[çc]a|prote[çc][õo]es?|verifica[çc][õo]es?|filtros?|regras?)/iu,
        name: "bypass_safety_pt",
        severity: :high,
        category: :instruction_override,
        confidence: 0.9
      },
      %{
        regex:
          ~r/(sou|eu\s+sou|como)\s+(o\s+|um\s+)?(administrador|root|super[\s-]?admin|s[íi]sadmin)/iu,
        name: "authority_escalation_pt",
        severity: :high,
        category: :instruction_override,
        confidence: 0.82
      },

      # System Extraction
      %{
        regex:
          ~r/(mostre|revele|exiba|imprima|me\s+diga|qual\s+[ée])\s+.{0,30}(seu\s+|o\s+)?(prompt|instru[çc][õo]es|regras)\s+(do\s+sistema|inicial|original|de\s+sistema)/iu,
        name: "show_system_prompt_pt",
        severity: :high,
        category: :system_extraction,
        confidence: 0.9
      },
      %{
        regex:
          ~r/(quais|qual)\s+(s[ãa]o|eram?)\s+(suas\s+|as\s+)?(instru[çc][õo]es|regras)\s+(iniciais|originais|de\s+sistema)/iu,
        name: "ask_initial_instructions_pt",
        severity: :high,
        category: :system_extraction,
        confidence: 0.88
      },
      %{
        regex: ~r/(repita|mostre|imprima)\s+(tudo|todo\s+o\s+texto)\s+.{0,20}(acima|antes)/iu,
        name: "repeat_above_pt",
        severity: :medium,
        category: :system_extraction,
        confidence: 0.82
      },

      # Mode Switching
      %{
        regex:
          ~r/(ative|ativa|entre\s+em|habilite|habilita)\s+(o\s+)?(modo\s+)?(desenvolvedor|administrador|debug|depura[çc][ãa]o|irrestrito)/iu,
        name: "enable_debug_mode_pt",
        severity: :high,
        category: :mode_switching,
        confidence: 0.9
      },
      %{
        regex:
          ~r/(desative|desativa|desligue|remova)\s+(todos\s+os\s+|os\s+)?(filtros|seguran[çc]a|restri[çc][õo]es|prote[çc][õo]es)/iu,
        name: "disable_filters_pt",
        severity: :high,
        category: :mode_switching,
        confidence: 0.88
      },

      # Role Manipulation
      %{
        regex:
          ~r/(voc[êe]\s+(agora\s+)?[ée]|seja|torne-se)\s+.{0,15}(DAN|sem\s+restri[çc][õo]es|irrestrito|sem\s+censura|desbloqueado)/iu,
        name: "role_unrestricted_pt",
        severity: :high,
        category: :role_manipulation,
        confidence: 0.88
      },
      %{
        regex:
          ~r/(finja|finge|aja|atue|imagine|fa[çc]a\s+de\s+conta)\s+que\s+(voc[êe]\s+)?n[ãa]o\s+(tem|possui|segue)\s+(limita[çc][õo]es|restri[çc][õo]es|regras|[ée]tica)/iu,
        name: "role_no_limits_pt",
        severity: :high,
        category: :role_manipulation,
        confidence: 0.88
      },
      %{
        regex:
          ~r/sem\s+(nenhuma\s+|nenhum\s+)?(restri[çc][õo]es?|limita[çc][õo]es?|filtros?|censura)/iu,
        name: "with_no_restrictions_pt",
        severity: :medium,
        category: :role_manipulation,
        confidence: 0.8
      }
    ]
  end

  @impl true
  def jailbreak_patterns do
    %{
      role_playing: [
        ~r/voc[êe]\s+(agora\s+)?[ée]\s+(o\s+)?(dan|dude|kevin|aim|chad)\b/iu,
        ~r/(finja|aja\s+como|interprete)\s+(que\s+voc[êe]\s+)?.*?(irrestrito|sem\s+censura|sem\s+regras)/iu,
        ~r/(voc[êe]\s+[ée])\s+.*?(sem|com\s+nenhuma?)\s+(restri[çc][õo]es?|limites?|regras?|[ée]tica)/iu,
        ~r/ignore\s+(todas\s+as\s+)?(diretrizes|regras|restri[çc][õo]es)\s+(de\s+seguran[çc]a|[ée]ticas?|morais?)/iu
      ],
      hypothetical_scenario: [
        ~r/hipoteticamente.*?(sem\s+restri[çc][õo]es?|irrestrito|permitido)/iu,
        ~r/(cen[áa]rio|mundo|realidade)\s+(hipot[ée]tic[oa]|fict[íi]ci[oa]|alternativ[oa]).*?(sem\s+regras?|sem\s+[ée]tica|sem\s+restri[çc][õo]es?|qualquer\s+coisa)/iu,
        ~r/imagine\s+(um\s+)?(cen[áa]rio|mundo)\s+onde.*?(sem\s+regras?|sem\s+[ée]tica|tudo\s+[ée]\s+permitido)/iu
      ],
      emotional_manipulation: [
        ~r/(apenas\s+)?para\s+fins?\s+(educacionais?|acad[êe]micos?|de\s+pesquisa)/iu,
        ~r/minha\s+av[óo]\s+(costumava|me\s+contava|me\s+ensinava)/iu,
        ~r/(sou|eu\s+sou)\s+(um[a]?\s+)?pesquisador[a]?\s+estudando/iu
      ]
    }
  end

  @impl true
  def pii_specs do
    [
      %{
        type: :cpf,
        regex: ~r/\d{3}\.\d{3}\.\d{3}-\d{2}|\b\d{11}\b/,
        validate: &BrValidation.valid_cpf?/1,
        confidence: 0.98
      },
      %{
        type: :cnpj,
        regex: ~r/\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}|\b\d{14}\b/,
        validate: &BrValidation.valid_cnpj?/1,
        confidence: 0.98
      },
      %{
        type: :cep,
        regex: ~r/\b\d{5}-\d{3}\b/,
        validate: &BrValidation.valid_cep?/1,
        confidence: 0.85
      },
      %{
        type: :br_phone,
        regex: ~r/(?:\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}/,
        validate: &BrValidation.valid_br_phone?/1,
        confidence: 0.9
      }
    ]
  end
end
