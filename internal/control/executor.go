package control

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

type Executor struct {
	DryRun bool
}

func (e Executor) Execute(ctx context.Context, plan Plan) ([]Result, error) {
	results := make([]Result, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		result := Result{Step: step, DryRun: e.DryRun}
		if step.Kind == StepWarning {
			results = append(results, result)
			continue
		}
		if e.DryRun {
			if step.Kind == StepCommand {
				if step.Command == nil {
					result.Error = "missing command"
					results = append(results, result)
					return results, fmt.Errorf("missing command for %s", step.Description)
				}
				result.Output = step.Command.String()
			} else if step.Kind == StepWrite {
				result.Output = fmt.Sprintf("write %s mode %s (%d bytes)", step.Path, step.Mode, len(step.Content))
			}
			results = append(results, result)
			continue
		}

		var err error
		switch step.Kind {
		case StepCommand:
			if step.Command == nil {
				err = fmt.Errorf("missing command for %s", step.Description)
			} else {
				result.Output, err = runCommand(ctx, *step.Command)
			}
		case StepWrite:
			err = writeFile(step.Path, step.Mode, []byte(step.Content))
		default:
			err = fmt.Errorf("unsupported step kind %q", step.Kind)
		}

		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func runCommand(ctx context.Context, command Command) (string, error) {
	if command.Program == "" {
		return "", fmt.Errorf("empty command program")
	}
	cmd := exec.CommandContext(ctx, command.Program, command.Args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), ctx.Err()
	}
	if err != nil {
		return string(output), fmt.Errorf("%s: %w: %s", command.String(), err, string(output))
	}
	return string(output), nil
}

func writeFile(path string, modeText string, content []byte) error {
	mode := os.FileMode(0o600)
	if modeText != "" {
		parsed, err := strconv.ParseUint(modeText, 8, 32)
		if err != nil {
			return fmt.Errorf("parse mode %q: %w", modeText, err)
		}
		mode = os.FileMode(parsed)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent for %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file for %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
