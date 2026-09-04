package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestMilterListenerActive(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:8895" || timeout != 250*time.Millisecond {
			t.Fatalf("dial called with network=%q address=%q timeout=%s", network, address, timeout)
		}
		return client, nil
	}
	if !milterListenerActiveUsing("tcp:127.0.0.1:8895", dial) {
		t.Fatal("active listener was not detected")
	}
	unavailable := func(string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	if milterListenerActiveUsing("tcp:127.0.0.1:8895", unavailable) {
		t.Fatal("closed listener was reported active")
	}
}
