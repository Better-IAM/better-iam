package cli

// Port of packages/cli/src/commands/shell.ts.

import (
	"context"
	"strings"
)

func flagNames(spec *CommandSpec) []string {
	var names []string
	for _, flag := range CommandFlags(spec) {
		if !flag.Hidden {
			names = append(names, "--"+flag.Name)
		}
	}
	return append(names, "--help")
}

func quote(text string) string { return "'" + strings.ReplaceAll(text, "'", `'\''`) + "'" }

func namesOf(spec *CommandSpec) []string { return append([]string{spec.Name}, spec.Aliases...) }

func bashCompletion(commands []*CommandSpec) string {
	var names []string
	for _, spec := range commands {
		names = append(names, namesOf(spec)...)
	}
	cases := make([]string, len(commands))
	for index, spec := range commands {
		var choices []string
		for _, flag := range CommandFlags(spec) {
			if flag.Choices != nil {
				choices = append(choices, `      --`+flag.Name+`) COMPREPLY=( $(compgen -W `+quote(strings.Join(flag.Choices, " "))+` -- "$cur") ); return ;;`)
			}
		}
		// A flag's value first (after --fail-on), then flag names for a word that starts with a dash; anything else
		// falls back to file names (complete -o default).
		lines := []string{"    " + strings.Join(namesOf(spec), "|") + ")"}
		if len(choices) > 0 {
			lines = append(lines, `      case "$prev" in`)
			lines = append(lines, choices...)
			lines = append(lines, "      esac")
		}
		lines = append(lines, `      case "$cur" in`,
			`        -*) COMPREPLY=( $(compgen -W `+quote(strings.Join(flagNames(spec), " "))+` -- "$cur") ) ;;`,
			"      esac ;;")
		cases[index] = strings.Join(lines, "\n")
	}
	return `# better-iam bash completion. Add to ~/.bashrc:  eval "$(better-iam completion bash)"
_better_iam() {
  local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W ` + quote(strings.Join(append([]string{"help"}, names...), " ")) + ` -- "$cur") )
    return
  fi
  if [ "${COMP_WORDS[1]}" = help ]; then
    COMPREPLY=( $(compgen -W ` + quote(strings.Join(names, " ")) + ` -- "$cur") )
    return
  fi
  case "${COMP_WORDS[1]}" in
` + strings.Join(cases, "\n") + `
  esac
}
complete -o default -F _better_iam better-iam
`
}

func zshCompletion(commands []*CommandSpec) string {
	lines := strings.Split(bashCompletion(commands), "\n")
	return `# better-iam zsh completion. Add to ~/.zshrc:  eval "$(better-iam completion zsh)"
autoload -U +X bashcompinit && bashcompinit
` + strings.Join(lines[1:], "\n")
}

func fishCompletion(commands []*CommandSpec) string {
	lines := []string{
		"# better-iam fish completion:  better-iam completion fish > ~/.config/fish/completions/better-iam.fish",
		"complete -c better-iam -f",
		"complete -c better-iam -n __fish_use_subcommand -a help -d " + quote("Show help for a command"),
	}
	for _, spec := range commands {
		for _, name := range namesOf(spec) {
			lines = append(lines, "complete -c better-iam -n __fish_use_subcommand -a "+name+" -d "+quote(spec.Summary))
		}
		for _, flag := range CommandFlags(spec) {
			if flag.Hidden {
				continue
			}
			values := " -r -F"
			if flag.Type == "boolean" {
				values = ""
			} else if flag.Choices != nil {
				values = " -x -a " + quote(strings.Join(flag.Choices, " "))
			}
			lines = append(lines, "complete -c better-iam -n "+quote("__fish_seen_subcommand_from "+spec.Name)+" -l "+flag.Name+values+" -d "+quote(flag.Description))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func powershellCompletion(commands []*CommandSpec) string {
	var table []string
	for _, spec := range commands {
		quoted := make([]string, 0)
		for _, flag := range flagNames(spec) {
			quoted = append(quoted, "'"+flag+"'")
		}
		for _, name := range namesOf(spec) {
			table = append(table, "  '"+name+"' = @("+strings.Join(quoted, ", ")+")")
		}
	}
	var choices []string
	for _, spec := range commands {
		for _, flag := range CommandFlags(spec) {
			if flag.Choices == nil {
				continue
			}
			values := make([]string, len(flag.Choices))
			for index, value := range flag.Choices {
				values[index] = "'" + value + "'"
			}
			choices = append(choices, "  '"+spec.Name+" --"+flag.Name+"' = @("+strings.Join(values, ", ")+")")
		}
	}
	return `# better-iam PowerShell completion. Add to $PROFILE:  better-iam completion powershell | Out-String | Invoke-Expression
$betterIamFlags = @{
` + strings.Join(table, "\n") + `
}
$betterIamChoices = @{
` + strings.Join(choices, "\n") + `
}
Register-ArgumentCompleter -Native -CommandName better-iam -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $words = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
  if ($words.Count -le 1 -or ($words.Count -eq 2 -and $wordToComplete)) {
    $candidates = @('help') + $betterIamFlags.Keys
  } else {
    $previous = if ($wordToComplete) { $words[-2] } else { $words[-1] }
    $key = "$($words[1]) $previous"
    if ($betterIamChoices.ContainsKey($key)) { $candidates = $betterIamChoices[$key] }
    elseif ($words[1] -eq 'help') { $candidates = $betterIamFlags.Keys }
    else { $candidates = $betterIamFlags[$words[1]] }
  }
  $candidates | Where-Object { $_ -like "$wordToComplete*" } | Sort-Object | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`
}

var shellCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "completion",
		Group:       "Shell",
		Summary:     "Print a shell completion script for commands, flags, and values",
		Description: "completion prints a completion script for bash, zsh, fish, or PowerShell covering every command, its flags, and the values of flags with fixed choices; load it from your shell profile. Project commands from the configuration are included when it is found.",
		Output:      "text",
		Args:        []ArgSpec{{Name: "shell", Description: "bash, zsh, fish, or powershell", Required: true}},
		Examples: []string{
			`eval "$(better-iam completion bash)"`,
			"better-iam completion fish > ~/.config/fish/completions/better-iam.fish",
			"better-iam completion powershell | Out-String | Invoke-Expression",
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			shell := c.Args[0]
			renderers := map[string]func([]*CommandSpec) string{
				"bash": bashCompletion, "zsh": zshCompletion, "fish": fishCompletion, "powershell": powershellCompletion,
				"pwsh": powershellCompletion,
			}
			render, ok := renderers[shell]
			if !ok {
				return nil, UsageError("completion supports bash, zsh, fish, and powershell (got " + shell + ")")
			}
			return render(c.Program.Commands), nil
		},
	}),
}
