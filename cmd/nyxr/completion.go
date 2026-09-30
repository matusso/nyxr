package main

import (
	"embed"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/matusso/nyxr/internal/config"
)

// Completion scripts are templates so profile names and port sets come from
// the same catalog the scanner uses and never drift from it.
//
//go:embed completions/*.tmpl
var completionFS embed.FS

var completionShells = []string{"bash", "zsh", "fish", "powershell"}

type completionItem struct {
	Name, Description string
}

type completionData struct {
	Profiles []completionItem
	PortSets []string
}

var completionTemplates = template.Must(template.New("").Funcs(template.FuncMap{
	// POSIX single-quoted string, valid in bash and zsh.
	"sh": func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" },
	"fish": func(s string) string {
		return "'" + strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace(s) + "'"
	},
	"ps":   func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" },
	"join": strings.Join,
}).ParseFS(completionFS, "completions/*.tmpl"))

func completionUsage(out io.Writer) error {
	_, err := fmt.Fprintf(out, `Usage: nyxr completion <shell>

Print a completion script for one of: %s.

  bash        source <(nyxr completion bash)
  zsh         nyxr completion zsh > "${fpath[1]}/_nyxr"
  fish        nyxr completion fish > ~/.config/fish/completions/nyxr.fish
  powershell  nyxr completion powershell | Out-String | Invoke-Expression
`, strings.Join(completionShells, ", "))
	return err
}

func runCompletion(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return completionUsage(out)
	}
	if len(args) != 1 {
		return fmt.Errorf("completion requires one shell: %s", strings.Join(completionShells, ", "))
	}
	shell := strings.ToLower(args[0])
	if shell == "pwsh" {
		shell = "powershell"
	}
	tmpl := completionTemplates.Lookup(shell + ".tmpl")
	if tmpl == nil {
		return fmt.Errorf("unsupported shell %q (supported: %s)", args[0], strings.Join(completionShells, ", "))
	}
	data := completionData{PortSets: config.PortSetNames()}
	// Planned profiles refuse to run, so offering them would only suggest errors.
	for _, p := range config.Profiles() {
		if p.Availability == config.StatusAvailable {
			data.Profiles = append(data.Profiles, completionItem{p.Name, p.Description})
		}
	}
	return tmpl.Execute(out, data)
}
