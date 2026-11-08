package keycheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Checkpoint хранится рядом с локальными результатами. Запись Raw необходима
// только для продолжения прерванного запуска и никогда не попадает в summary.
type Checkpoint struct {
	mu      sync.Mutex
	Records map[string]Record
	Started map[string]bool
	Results map[string]Result
}

type checkpointDisk struct {
	Records []checkpointRecord `json:"records"`
	Started []string           `json:"started"`
	Results []Result           `json:"results"`
}

type checkpointRecord struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	Raw  string `json:"raw"`
}

func LoadCheckpoint(dir string) (*Checkpoint, error) {
	path := filepath.Join(dir, "state.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newCheckpoint(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("keycheck: read state: %w", err)
	}
	var disk checkpointDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("keycheck: decode state: %w", err)
	}
	checkpoint := newCheckpoint()
	for _, record := range disk.Records {
		if record.ID == "" || record.Raw == "" {
			return nil, errors.New("keycheck: invalid state record")
		}
		checkpoint.Records[record.ID] = Record{ID: record.ID, Kind: record.Kind, Raw: record.Raw}
	}
	for _, id := range disk.Started {
		checkpoint.Started[id] = true
	}
	for _, result := range disk.Results {
		checkpoint.Results[result.RecordID] = result
	}
	return checkpoint, nil
}

func newCheckpoint() *Checkpoint {
	return &Checkpoint{Records: make(map[string]Record), Started: make(map[string]bool), Results: make(map[string]Result)}
}

func (c *Checkpoint) MarkStarted(record Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Records[record.ID] = record
	c.Started[record.ID] = true
}

func (c *Checkpoint) MarkCompleted(result Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Results[result.RecordID] = result
}

// Pending возвращает только ещё не начатые записи. Повтор начатой пробы без
// новой явной команды запрещён, даже если процесс завершился аварийно.
func (c *Checkpoint) Pending(records []Record) []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := make([]Record, 0, len(records))
	for _, record := range records {
		if !c.Started[record.ID] && c.Results[record.ID].RecordID == "" {
			pending = append(pending, record)
		}
	}
	return pending
}

func (c *Checkpoint) Save(dir string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	disk := checkpointDisk{}
	for _, record := range c.Records {
		disk.Records = append(disk.Records, checkpointRecord{ID: record.ID, Kind: record.Kind, Raw: record.Raw})
	}
	for id := range c.Started {
		disk.Started = append(disk.Started, id)
	}
	for _, result := range c.Results {
		disk.Results = append(disk.Results, result)
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("keycheck: encode state: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keycheck: create state directory: %w", err)
	}
	return writePrivate(filepath.Join(dir, "state.json"), string(data)+"\n")
}
