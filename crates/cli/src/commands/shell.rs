//! Shell completion scripts (`commands/shell.ts`).

use std::sync::Arc;

use serde_json::Value;

use crate::errors::usage_error;
use crate::framework::{
    ArgSpec, CommandOutput, CommandSpec, FlagType, command_flags, define_command,
};

type Spec = Arc<CommandSpec>;

fn flag_names(spec: &CommandSpec) -> Vec<String> {
    command_flags(spec)
        .into_iter()
        .filter(|(_, flag)| !flag.hidden)
        .map(|(name, _)| format!("--{name}"))
        .chain(std::iter::once("--help".to_owned()))
        .collect()
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn names_of(spec: &CommandSpec) -> Vec<String> {
    std::iter::once(spec.name.clone())
        .chain(spec.aliases.iter().cloned())
        .collect()
}

fn bash(commands: &[Spec]) -> String {
    let names: Vec<String> = commands.iter().flat_map(|spec| names_of(spec)).collect();
    let cases: Vec<String> = commands
        .iter()
        .map(|spec| {
            let choices: Vec<String> = command_flags(spec)
                .into_iter()
                .filter_map(|(name, flag)| {
                    flag.choices.map(|choices| {
                        format!(
                            "      --{name}) COMPREPLY=( $(compgen -W {} -- \"$cur\") ); return ;;",
                            quote(&choices.join(" "))
                        )
                    })
                })
                .collect();
            // A flag's value first (after --fail-on), then flag names for a word that starts with a dash; anything
            // else falls back to file names (`complete -o default`).
            let mut lines = vec![format!("    {})", names_of(spec).join("|"))];
            if !choices.is_empty() {
                lines.push("      case \"$prev\" in".into());
                lines.extend(choices);
                lines.push("      esac".into());
            }
            lines.push("      case \"$cur\" in".into());
            lines.push(format!(
                "        -*) COMPREPLY=( $(compgen -W {} -- \"$cur\") ) ;;",
                quote(&flag_names(spec).join(" "))
            ));
            lines.push("      esac ;;".into());
            lines.join("\n")
        })
        .collect();
    let mut first = vec!["help".to_owned()];
    first.extend(names.iter().cloned());
    format!(
        "# better-iam bash completion. Add to ~/.bashrc:  eval \"$(better-iam completion bash)\"
_better_iam() {{
  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\" prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"
  if [ \"$COMP_CWORD\" -eq 1 ]; then
    COMPREPLY=( $(compgen -W {} -- \"$cur\") )
    return
  fi
  if [ \"${{COMP_WORDS[1]}}\" = help ]; then
    COMPREPLY=( $(compgen -W {} -- \"$cur\") )
    return
  fi
  case \"${{COMP_WORDS[1]}}\" in
{}
  esac
}}
complete -o default -F _better_iam better-iam
",
        quote(&first.join(" ")),
        quote(&names.join(" ")),
        cases.join("\n")
    )
}

fn zsh(commands: &[Spec]) -> String {
    let script = bash(commands);
    let rest: Vec<&str> = script.split('\n').skip(1).collect();
    format!(
        "# better-iam zsh completion. Add to ~/.zshrc:  eval \"$(better-iam completion zsh)\"\nautoload -U +X bashcompinit && bashcompinit\n{}",
        rest.join("\n")
    )
}

fn fish(commands: &[Spec]) -> String {
    let mut lines = vec![
        "# better-iam fish completion:  better-iam completion fish > ~/.config/fish/completions/better-iam.fish"
            .to_owned(),
        "complete -c better-iam -f".to_owned(),
        format!(
            "complete -c better-iam -n __fish_use_subcommand -a help -d {}",
            quote("Show help for a command")
        ),
    ];
    for spec in commands {
        for name in names_of(spec) {
            lines.push(format!(
                "complete -c better-iam -n __fish_use_subcommand -a {name} -d {}",
                quote(&spec.summary)
            ));
        }
        for (name, flag) in command_flags(spec) {
            if flag.hidden {
                continue;
            }
            let values = if flag.kind == FlagType::Boolean {
                String::new()
            } else if let Some(choices) = &flag.choices {
                format!(" -x -a {}", quote(&choices.join(" ")))
            } else {
                " -r -F".to_owned()
            };
            lines.push(format!(
                "complete -c better-iam -n {} -l {name}{values} -d {}",
                quote(&format!("__fish_seen_subcommand_from {}", spec.name)),
                quote(&flag.description)
            ));
        }
    }
    format!("{}\n", lines.join("\n"))
}

fn powershell(commands: &[Spec]) -> String {
    let table: Vec<String> = commands
        .iter()
        .flat_map(|spec| {
            let flags = flag_names(spec)
                .iter()
                .map(|flag| format!("'{flag}'"))
                .collect::<Vec<_>>()
                .join(", ");
            names_of(spec)
                .into_iter()
                .map(move |name| format!("  '{name}' = @({flags})"))
                .collect::<Vec<_>>()
        })
        .collect();
    let choices: Vec<String> = commands
        .iter()
        .flat_map(|spec| {
            command_flags(spec)
                .into_iter()
                .filter_map(|(name, flag)| {
                    flag.choices.map(|choices| {
                        format!(
                            "  '{} --{name}' = @({})",
                            spec.name,
                            choices
                                .iter()
                                .map(|value| format!("'{value}'"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();
    format!(
        "# better-iam PowerShell completion. Add to $PROFILE:  better-iam completion powershell | Out-String | Invoke-Expression
$betterIamFlags = @{{
{}
}}
$betterIamChoices = @{{
{}
}}
Register-ArgumentCompleter -Native -CommandName better-iam -ScriptBlock {{
  param($wordToComplete, $commandAst, $cursorPosition)
  $words = @($commandAst.CommandElements | ForEach-Object {{ $_.ToString() }})
  if ($words.Count -le 1 -or ($words.Count -eq 2 -and $wordToComplete)) {{
    $candidates = @('help') + $betterIamFlags.Keys
  }} else {{
    $previous = if ($wordToComplete) {{ $words[-2] }} else {{ $words[-1] }}
    $key = \"$($words[1]) $previous\"
    if ($betterIamChoices.ContainsKey($key)) {{ $candidates = $betterIamChoices[$key] }}
    elseif ($words[1] -eq 'help') {{ $candidates = $betterIamFlags.Keys }}
    else {{ $candidates = $betterIamFlags[$words[1]] }}
  }}
  $candidates | Where-Object {{ $_ -like \"$wordToComplete*\" }} | Sort-Object | ForEach-Object {{
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }}
}}
",
        table.join("\n"),
        choices.join("\n")
    )
}

pub fn shell_commands() -> Vec<CommandSpec> {
    vec![
        define_command(
            "completion",
            "Print a shell completion script for commands, flags, and values",
            |context| async move {
                let shell = context.args[0].as_str();
                let commands = &context.program.commands;
                let script = match shell {
                    "bash" => bash(commands),
                    "zsh" => zsh(commands),
                    "fish" => fish(commands),
                    "powershell" | "pwsh" => powershell(commands),
                    _ => {
                        return Err(usage_error(
                            format!("completion supports bash, zsh, fish, and powershell (got {shell})"),
                            None,
                        ));
                    }
                };
                Ok(Some(Value::String(script)))
            },
        )
        .group("Shell")
        .description(
            "completion prints a completion script for bash, zsh, fish, or PowerShell covering every command, its flags, and the values of flags with fixed choices; load it from your shell profile. Project commands added with create_cli are included.",
        )
        .output(CommandOutput::Text)
        .arg(ArgSpec::new("shell", "bash, zsh, fish, or powershell").required())
        .examples(&[
            "eval \"$(better-iam completion bash)\"",
            "better-iam completion fish > ~/.config/fish/completions/better-iam.fish",
            "better-iam completion powershell | Out-String | Invoke-Expression",
        ]),
    ]
}
