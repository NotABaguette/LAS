package control

import (
	"encoding/json"
	"fmt"
	"strings"
)

type StepKind string

const (
	StepCommand StepKind = "command"
	StepWrite   StepKind = "write_file"
	StepWarning StepKind = "warning"
)

type Plan struct {
	Steps []Step `json:"steps"`
}

type Step struct {
	Kind        StepKind `json:"kind"`
	Description string   `json:"description"`
	Command     *Command `json:"command,omitempty"`
	Path        string   `json:"path,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Content     string   `json:"content,omitempty"`
}

type Command struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
}

type Result struct {
	Step        Step   `json:"step"`
	Output      string `json:"output"`
	Error       string `json:"error,omitempty"`
	DryRun      bool   `json:"dryRun"`
	Interrupted bool   `json:"interrupted"`
}

func (p *Plan) AddCommand(description string, program string, args ...string) {
	p.Steps = append(p.Steps, Step{
		Kind:        StepCommand,
		Description: description,
		Command: &Command{
			Program: program,
			Args:    args,
		},
	})
}

func (p *Plan) AddWrite(description, path, mode, content string) {
	p.Steps = append(p.Steps, Step{
		Kind:        StepWrite,
		Description: description,
		Path:        path,
		Mode:        mode,
		Content:     content,
	})
}

func (p *Plan) AddWarning(format string, args ...any) {
	p.Steps = append(p.Steps, Step{
		Kind:        StepWarning,
		Description: fmt.Sprintf(format, args...),
	})
}

func (p Plan) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

func (c Command) String() string {
	parts := append([]string{c.Program}, c.Args...)
	for i, part := range parts {
		parts[i] = shellQuote(part)
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z') &&
			!(r >= 'a' && r <= 'z') &&
			!(r >= '0' && r <= '9') &&
			!strings.ContainsRune("@%_+=:,./-", r)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
