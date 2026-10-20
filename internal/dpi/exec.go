package dpi

import (
	"context"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ExecRunner — настоящие процессы.
type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, bin string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).CombinedOutput()
}

func (ExecRunner) Start(bin string, args []string, out io.Writer) (Process, error) {
	c := exec.Command(bin, args...)
	c.Stdout, c.Stderr = out, out
	if err := c.Start(); err != nil {
		return nil, err
	}
	p := &execProc{c: c, done: make(chan struct{})}
	go func() { p.err = c.Wait(); close(p.done) }()
	return p, nil
}

type execProc struct {
	c    *exec.Cmd
	done chan struct{}
	err  error
	once sync.Once
}

func (p *execProc) Wait() error {
	<-p.done
	return p.err
}

// Stop — мягко (SIGTERM), через 3 с — принудительно.
func (p *execProc) Stop() error {
	p.once.Do(func() {
		if p.c.Process.Signal(syscall.SIGTERM) != nil {
			_ = p.c.Process.Kill()
		}
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			_ = p.c.Process.Kill()
			<-p.done
		}
	})
	return nil
}
