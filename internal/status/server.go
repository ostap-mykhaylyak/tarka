package status

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// The control socket speaks one JSON request / one JSON response per
// connection. "status" returns the Snapshot; the dns01 commands are
// the ACME hook surface behind tarka --dns01-set / --dns01-clear.
type request struct {
	Cmd   string `json:"cmd"` // status | dns01-set | dns01-clear
	Name  string `json:"name,omitempty"`
	Token string `json:"token,omitempty"`
}

// opResult is the response to a mutating command.
type opResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Handlers are the daemon-side implementations of the socket
// commands. Nil handlers answer with an error.
type Handlers struct {
	Status     func() *Snapshot
	DNS01Set   func(domain, token string) error
	DNS01Clear func(domain, token string) error
}

// Server is the local Unix control socket the daemon exposes for
// --status and the dns01 commands. It never crosses the network: no
// public bind, covered by the systemd hardening.
type Server struct {
	ln   net.Listener
	path string
}

// Serve starts listening on the Unix socket at path. A stale socket
// left by a previous crash is removed first.
func Serve(path string, h Handlers) (*Server, error) {
	if err := os.MkdirAll(socketDir(path), 0o750); err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	// Remove a stale socket from a previous crash.
	if _, err := os.Stat(path); err == nil {
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	os.Chmod(path, 0o660)

	s := &Server{ln: ln, path: path}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on shutdown
			}
			go serveConn(conn, h)
		}
	}()
	return s, nil
}

func serveConn(c net.Conn, h Handlers) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	var req request
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		json.NewEncoder(c).Encode(opResult{Error: "bad request: " + err.Error()})
		return
	}

	switch req.Cmd {
	case "status":
		if h.Status == nil {
			json.NewEncoder(c).Encode(opResult{Error: "status unavailable"})
			return
		}
		json.NewEncoder(c).Encode(h.Status())
	case "dns01-set":
		respond(c, h.DNS01Set, req)
	case "dns01-clear":
		respond(c, h.DNS01Clear, req)
	default:
		json.NewEncoder(c).Encode(opResult{Error: fmt.Sprintf("unknown command %q", req.Cmd)})
	}
}

func respond(c net.Conn, fn func(string, string) error, req request) {
	if fn == nil {
		json.NewEncoder(c).Encode(opResult{Error: "command unavailable"})
		return
	}
	if err := fn(req.Name, req.Token); err != nil {
		json.NewEncoder(c).Encode(opResult{Error: err.Error()})
		return
	}
	json.NewEncoder(c).Encode(opResult{OK: true})
}

// Close stops the listener and removes the socket file.
func (s *Server) Close() error {
	err := s.ln.Close()
	os.Remove(s.path)
	return err
}
