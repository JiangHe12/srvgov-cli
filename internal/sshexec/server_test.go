package sshexec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

type testSSHServer struct {
	listener net.Listener

	mu               sync.RWMutex
	hostKey          ssh.Signer
	acceptedKey      ssh.PublicKey
	password         string
	lastAuth         string
	stdout           string
	stderr           string
	exitCode         uint32
	receivedStdin    string
	ptyRequested     atomic.Bool
	blockSessionOpen atomic.Bool
	sessionOpenGate  <-chan struct{}
	sessionRequested chan<- struct{}
	stopOnce         sync.Once
	connectionGroup  sync.WaitGroup
}

func newTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	server := &testSSHServer{
		listener: listener,
		hostKey:  newTestSigner(t),
		stdout:   "stdout-data",
		stderr:   "stderr-data",
		exitCode: 7,
	}
	server.connectionGroup.Add(1)
	go server.serve()
	t.Cleanup(server.close)
	return server
}

func (s *testSSHServer) address() string {
	return s.listener.Addr().String()
}

func (s *testSSHServer) setHostKey(signer ssh.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostKey = signer
}

func (s *testSSHServer) setPublicKey(key ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedKey = key
	s.password = ""
}

func (s *testSSHServer) setPassword(password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedKey = nil
	s.password = password
}

func (s *testSSHServer) setOutput(stdout, stderr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stdout = stdout
	s.stderr = stderr
}

func (s *testSSHServer) setBlockSessionOpen(block bool) {
	s.blockSessionOpen.Store(block)
}

func (s *testSSHServer) setSessionOpenGate(gate <-chan struct{}, requested chan<- struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionOpenGate = gate
	s.sessionRequested = requested
}

func (s *testSSHServer) authentication() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastAuth
}

func (s *testSSHServer) stdin() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.receivedStdin
}

func (s *testSSHServer) serve() {
	defer s.connectionGroup.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.connectionGroup.Add(1)
		go func() {
			defer s.connectionGroup.Done()
			s.handleConnection(connection)
		}()
	}
}

func (s *testSSHServer) handleConnection(connection net.Conn) {
	defer func() { _ = connection.Close() }()

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.acceptedKey != nil && bytes.Equal(s.acceptedKey.Marshal(), key.Marshal()) {
				s.lastAuth = "publickey"
				return nil, nil
			}
			return nil, errRejectedAuth
		},
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.password != "" && s.password == string(password) {
				s.lastAuth = "password"
				return nil, nil
			}
			return nil, errRejectedAuth
		},
	}
	s.mu.RLock()
	config.AddHostKey(s.hostKey)
	s.mu.RUnlock()

	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		if s.blockSessionOpen.Load() {
			continue
		}
		s.mu.RLock()
		gate := s.sessionOpenGate
		requested := s.sessionRequested
		s.mu.RUnlock()
		if requested != nil {
			select {
			case requested <- struct{}{}:
			default:
			}
		}
		if gate != nil {
			<-gate
		}
		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(channel, channelRequests)
	}
}

func (s *testSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		switch request.Type {
		case "pty-req":
			s.ptyRequested.Store(true)
			_ = request.Reply(false, nil)
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
				_ = request.Reply(false, nil)
				return
			}
			_ = request.Reply(true, nil)
			if strings.HasPrefix(payload.Command, "tee ") {
				input, _ := io.ReadAll(channel)
				s.mu.Lock()
				s.receivedStdin = string(input)
				s.mu.Unlock()
			}
			s.mu.RLock()
			stdout := s.stdout
			stderr := s.stderr
			exitCode := s.exitCode
			s.mu.RUnlock()
			_, _ = io.WriteString(channel, stdout)
			_, _ = io.WriteString(channel.Stderr(), stderr)
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, exitCode)
			_, _ = channel.SendRequest("exit-status", false, status)
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
}

func (s *testSSHServer) close() {
	s.stopOnce.Do(func() {
		_ = s.listener.Close()
		s.connectionGroup.Wait()
	})
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, signer := newTestKey(t)
	return signer
}

func newTestKey(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return privateKey, signer
}

func newTestRSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return signer
}
