package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/PhilAnderson1/SentinelMilter/internal/ai"
	"github.com/PhilAnderson1/SentinelMilter/internal/config"
	"github.com/PhilAnderson1/SentinelMilter/internal/milter"
)

func main() {
	configPath := flag.String("config", "/etc/sentinelmilter/sentinelmilter.yaml", "configuration file")
	check := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Println("configuration is valid")
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))
	prompt, err := os.ReadFile(cfg.AI.PromptFile)
	if err != nil {
		logger.Error("cannot read detection prompt", "error", err)
		os.Exit(2)
	}
	client := ai.NewClient(cfg.AI, string(prompt))

	ln, cleanup, err := listen(cfg.Milter.Socket)
	if err != nil {
		logger.Error("cannot create milter listener", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server := milter.NewServer(cfg, client, logger)
	logger.Info("SentinelMilter started", "socket", cfg.Milter.Socket, "mode", cfg.Mode)
	if err := server.Serve(ctx, ln); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("milter server stopped", "error", err)
		os.Exit(1)
	}
}

func listen(address string) (net.Listener, func(), error) {
	if strings.HasPrefix(address, "unix:") {
		path := strings.TrimPrefix(address, "unix:")
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, func() {}, err
		}
		if st, err := os.Lstat(path); err == nil {
			if st.Mode()&os.ModeSocket == 0 {
				return nil, func() {}, fmt.Errorf("refusing to replace non-socket path %s", path)
			}
			if err := os.Remove(path); err != nil {
				return nil, func() {}, err
			}
		} else if !os.IsNotExist(err) {
			return nil, func() {}, err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, func() {}, err
		}
		_ = os.Chmod(path, 0660)
		return ln, func() { _ = ln.Close(); _ = os.Remove(path) }, nil
	}
	if strings.HasPrefix(address, "tcp:") {
		ln, err := net.Listen("tcp", strings.TrimPrefix(address, "tcp:"))
		return ln, func() {
			if ln != nil {
				_ = ln.Close()
			}
		}, err
	}
	return nil, func() {}, fmt.Errorf("socket must begin with unix: or tcp:")
}
