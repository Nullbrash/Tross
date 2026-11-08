package keycheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// WriteOutputs сохраняет локальные результаты. В summary.json намеренно нет
// исходных строк: связь с ключом возможна только через record_id в закрытых
// текстовых списках.
func WriteOutputs(dir string, records []Record, results []Result) error {
	if dir == "" {
		return errors.New("keycheck: output directory is required")
	}
	byID := make(map[string]string, len(records))
	for _, record := range records {
		if record.ID == "" || record.Raw == "" {
			return errors.New("keycheck: record id and raw value are required")
		}
		byID[record.ID] = record.Raw
	}
	working, unstable, notWorking, unresolved := make([]string, 0), make([]string, 0), make([]string, 0), make([]string, 0)
	for _, result := range results {
		raw, ok := byID[result.RecordID]
		if !ok {
			return fmt.Errorf("keycheck: result for unknown record %q", result.RecordID)
		}
		line := result.RecordID + "\t" + raw + "\n"
		switch result.Status {
		case "working":
			working = append(working, line)
		case "unstable":
			unstable = append(unstable, line)
		case "not_working":
			notWorking = append(notWorking, line)
		default:
			unresolved = append(unresolved, line)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keycheck: create output directory: %w", err)
	}
	if err := writePrivate(filepath.Join(dir, "working.txt"), strings.Join(working, "")); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(dir, "not_working.txt"), strings.Join(notWorking, "")); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(dir, "unstable.txt"), strings.Join(unstable, "")); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(dir, "unresolved.txt"), strings.Join(unresolved, "")); err != nil {
		return err
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RecordID < results[j].RecordID })
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("keycheck: encode summary: %w", err)
	}
	return writePrivate(filepath.Join(dir, "summary.json"), string(data)+"\n")
}

func writePrivate(path, content string) error {
	if runtime.GOOS == "windows" {
		// В Windows песочница тестов запрещает rename временного файла, хотя
		// каталог уже создан нами. Права всё равно выставляются до возврата.
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return fmt.Errorf("keycheck: write %s: %w", filepath.Base(path), err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("keycheck: protect %s: %w", filepath.Base(path), err)
		}
		return nil
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(content), 0o600); err != nil {
		return fmt.Errorf("keycheck: write %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return fmt.Errorf("keycheck: protect %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("keycheck: replace %s: %w", filepath.Base(path), err)
	}
	return nil
}
