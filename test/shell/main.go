package main

import (
	"log/slog"
	"os"

	"github.com/cilium/cilium/pkg/hive"
	client "github.com/cilium/cilium/pkg/shell/client"
	server "github.com/cilium/cilium/pkg/shell/server"
)

func main() {
	if os.Args[1] == "server" {
		h := hive.New(server.Cell)
		err := h.Run(slog.Default())
		if err != nil {
			slog.Error("Failed to run shell server", "error", err)
		}
		return
	}

	if os.Args[1] == "client" {
		client.ShellCmd.Run(client.ShellCmd, os.Args[2:])
	}
}
