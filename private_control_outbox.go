package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const privateControlCommandStoreVersion = 1

type privateControlCommandStore struct {
	filename string
}

type privateControlPersistedCommands struct {
	Version  int                                    `json:"version"`
	Commands []privateControlRevokeServiceAdmission `json:"commands"`
}

func openPrivateControlCommandStore(filename string, now time.Time) (*privateControlCommandStore, map[string]*privateControlPendingCommand, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return nil, nil, errors.New("Private Control Link command store file is required")
	}
	store := &privateControlCommandStore{filename: filename}
	commands, err := store.load()
	if err != nil {
		return nil, nil, err
	}
	pending := make(map[string]*privateControlPendingCommand, len(commands))
	expired := false
	for _, command := range commands {
		if !validPrivateControlRevocation(command) {
			return nil, nil, errors.New("Private Control Link command store contains an invalid command")
		}
		if _, duplicate := pending[command.MessageID]; duplicate {
			return nil, nil, errors.New("Private Control Link command store contains a duplicate message ID")
		}
		if command.DenyUntil <= now.Unix() {
			expired = true
			continue
		}
		pending[command.MessageID] = &privateControlPendingCommand{
			message: command,
			result:  make(chan privateControlCommandResult, 1),
		}
	}
	if len(pending) > privateControlMaxPendingCommands {
		return nil, nil, errors.New("Private Control Link command store exceeds the pending command limit")
	}
	if expired {
		if err := store.persist(pending); err != nil {
			return nil, nil, err
		}
	}
	return store, pending, nil
}

func (s *privateControlCommandStore) load() ([]privateControlRevokeServiceAdmission, error) {
	info, err := os.Stat(s.filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat Private Control Link command store: %w", err)
	}
	if info.Size() > privateControlMaxPendingCommands*1024 {
		return nil, errors.New("Private Control Link command store is too large")
	}
	data, err := os.ReadFile(s.filename)
	if err != nil {
		return nil, fmt.Errorf("read Private Control Link command store: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var stored privateControlPersistedCommands
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode Private Control Link command store: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("Private Control Link command store must contain one JSON object")
	}
	if stored.Version != privateControlCommandStoreVersion || stored.Commands == nil {
		return nil, errors.New("Private Control Link command store has an unsupported format")
	}
	return stored.Commands, nil
}

func (s *privateControlCommandStore) persist(pending map[string]*privateControlPendingCommand) error {
	commands := make([]privateControlRevokeServiceAdmission, 0, len(pending))
	for _, command := range pending {
		commands = append(commands, command.message)
	}
	sort.Slice(commands, func(left, right int) bool {
		return commands[left].MessageID < commands[right].MessageID
	})
	data, err := json.Marshal(privateControlPersistedCommands{
		Version:  privateControlCommandStoreVersion,
		Commands: commands,
	})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	directory := filepath.Dir(s.filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Private Control Link command-store directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".pcl-revocations-")
	if err != nil {
		return fmt.Errorf("create Private Control Link command-store temp file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("restrict Private Control Link command-store permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write Private Control Link command store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync Private Control Link command store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Private Control Link command store: %w", err)
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(s.filename); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replace Private Control Link command store: %w", err)
		}
	}
	if err := os.Rename(temporaryName, s.filename); err != nil {
		return fmt.Errorf("commit Private Control Link command store: %w", err)
	}
	if runtime.GOOS != "windows" {
		directoryHandle, err := os.Open(directory)
		if err != nil {
			return fmt.Errorf("open Private Control Link command-store directory: %w", err)
		}
		err = directoryHandle.Sync()
		closeErr := directoryHandle.Close()
		if err != nil {
			return fmt.Errorf("sync Private Control Link command-store directory: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("close Private Control Link command-store directory: %w", closeErr)
		}
	}
	return nil
}
