package cli

import "fmt"

func cmdCompletions(args []string) int {
	if len(args) != 1 {
		return failUsage("sec completions bash|zsh|fish")
	}
	shell := args[0]
	var out string
	switch shell {
	case "bash":
		out = bashCompletions
	case "zsh":
		out = zshCompletions
	case "fish":
		out = fishCompletions
	default:
		return failUsage("sec completions bash|zsh|fish")
	}
	fmt.Print(out)
	return 0
}

const bashCompletions = `_sec() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    commands="init add get list update rm rotate rollback versions rotate-master export import tokens serve status audit completions help"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
    fi
}
complete -F _sec sec
`

const zshCompletions = `#compdef sec
_sec() {
    local -a commands
    commands=(
        'init:create a new vault'
        'add:store a new secret'
        'get:print a secret or project'
        'list:list secrets'
        'update:replace a secret value'
        'rm:delete a secret'
        'rotate:regenerate a secret'
        'rollback:restore a version'
        'versions:show version history'
        'rotate-master:change master password'
        'export:backup or export secrets'
        'import:import from env/json'
        'tokens:manage API tokens'
        'serve:start the HTTP API'
        'status:vault health'
        'audit:show audit log'
        'completions:generate completions'
    )
    if (( CURRENT == 2 )); then
        _describe 'command' commands
    fi
}
compdef _sec sec
`

const fishCompletions = `complete -c sec -f
complete -c sec -n '__fish_use_subcommand' -a 'init add get list update rm rotate rollback versions rotate-master export import tokens serve status audit completions help'
`
