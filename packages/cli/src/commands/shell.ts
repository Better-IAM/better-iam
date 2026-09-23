import { usageError } from '../errors.js';
import { commandFlags, defineCommand, type CommandSpec } from '../framework.js';

type Spec = CommandSpec<any>;

function flagNames(spec: Spec): string[] {
  return Object.entries(commandFlags(spec))
    .filter(([, flag]) => !flag.hidden)
    .map(([name]) => `--${name}`)
    .concat('--help');
}

const quote = (text: string) => `'${text.replace(/'/g, `'\\''`)}'`;

function bash(commands: readonly Spec[]): string {
  const names = commands.flatMap((spec) => [spec.name, ...(spec.aliases ?? [])]);
  const cases = commands.map((spec) => {
    const choices = Object.entries(commandFlags(spec))
      .filter(([, flag]) => flag.choices)
      .map(
        ([name, flag]) =>
          `      --${name}) COMPREPLY=( $(compgen -W ${quote(flag.choices!.join(' '))} -- "$cur") ); return ;;`,
      );
    // A flag's value first (after --fail-on), then flag names for a word that starts with a dash; anything else
    // falls back to file names (`complete -o default`).
    return [
      `    ${[spec.name, ...(spec.aliases ?? [])].join('|')})`,
      ...(choices.length ? ['      case "$prev" in', ...choices, '      esac'] : []),
      '      case "$cur" in',
      `        -*) COMPREPLY=( $(compgen -W ${quote(flagNames(spec).join(' '))} -- "$cur") ) ;;`,
      '      esac ;;',
    ].join('\n');
  });
  return `# better-iam bash completion. Add to ~/.bashrc:  eval "$(better-iam completion bash)"
_better_iam() {
  local cur="\${COMP_WORDS[COMP_CWORD]}" prev="\${COMP_WORDS[COMP_CWORD-1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W ${quote(['help', ...names].join(' '))} -- "$cur") )
    return
  fi
  if [ "\${COMP_WORDS[1]}" = help ]; then
    COMPREPLY=( $(compgen -W ${quote(names.join(' '))} -- "$cur") )
    return
  fi
  case "\${COMP_WORDS[1]}" in
${cases.join('\n')}
  esac
}
complete -o default -F _better_iam better-iam
`;
}

function zsh(commands: readonly Spec[]): string {
  return `# better-iam zsh completion. Add to ~/.zshrc:  eval "$(better-iam completion zsh)"
autoload -U +X bashcompinit && bashcompinit
${bash(commands).split('\n').slice(1).join('\n')}`;
}

function fish(commands: readonly Spec[]): string {
  const lines = [
    '# better-iam fish completion:  better-iam completion fish > ~/.config/fish/completions/better-iam.fish',
    'complete -c better-iam -f',
    `complete -c better-iam -n __fish_use_subcommand -a help -d ${quote('Show help for a command')}`,
  ];
  for (const spec of commands) {
    for (const name of [spec.name, ...(spec.aliases ?? [])])
      lines.push(
        `complete -c better-iam -n __fish_use_subcommand -a ${name} -d ${quote(spec.summary)}`,
      );
    for (const [name, flag] of Object.entries(commandFlags(spec))) {
      if (flag.hidden) continue;
      const values =
        flag.type === 'boolean'
          ? ''
          : flag.choices
            ? ` -x -a ${quote(flag.choices.join(' '))}`
            : ' -r -F';
      lines.push(
        `complete -c better-iam -n ${quote(`__fish_seen_subcommand_from ${spec.name}`)} -l ${name}${values} -d ${quote(flag.description)}`,
      );
    }
  }
  return lines.join('\n') + '\n';
}

function powershell(commands: readonly Spec[]): string {
  const table = commands
    .flatMap((spec) =>
      [spec.name, ...(spec.aliases ?? [])].map(
        (name) =>
          `  '${name}' = @(${flagNames(spec)
            .map((flag) => `'${flag}'`)
            .join(', ')})`,
      ),
    )
    .join('\n');
  const choices = commands
    .flatMap((spec) =>
      Object.entries(commandFlags(spec))
        .filter(([, flag]) => flag.choices)
        .map(
          ([name, flag]) =>
            `  '${spec.name} --${name}' = @(${flag.choices!.map((value) => `'${value}'`).join(', ')})`,
        ),
    )
    .join('\n');
  return `# better-iam PowerShell completion. Add to $PROFILE:  better-iam completion powershell | Out-String | Invoke-Expression
$betterIamFlags = @{
${table}
}
$betterIamChoices = @{
${choices}
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
`;
}

export const shellCommands = [
  defineCommand({
    name: 'completion',
    group: 'Shell',
    summary: 'Print a shell completion script for commands, flags, and values',
    description:
      'completion prints a completion script for bash, zsh, fish, or PowerShell covering every command, its flags, and the values of flags with fixed choices; load it from your shell profile. Project commands from the configuration are included when it is found.',
    output: 'text',
    args: [{ name: 'shell', description: 'bash, zsh, fish, or powershell', required: true }],
    examples: [
      'eval "$(better-iam completion bash)"',
      'better-iam completion fish > ~/.config/fish/completions/better-iam.fish',
      'better-iam completion powershell | Out-String | Invoke-Expression',
    ],
    run({ args, program }) {
      const shell = args[0]!;
      const renderers: Record<string, (commands: readonly Spec[]) => string> = {
        bash,
        zsh,
        fish,
        powershell,
        pwsh: powershell,
      };
      const render = Object.hasOwn(renderers, shell) ? renderers[shell] : undefined;
      if (!render)
        throw usageError(`completion supports bash, zsh, fish, and powershell (got ${shell})`);
      return render(program.commands);
    },
  }),
];
