package main

import (
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
)

func nolvsPresent() bool {
	if _, err := os.Stat("/etc/nolvs"); err == nil {
		return true
	}
	return false
}

type HijackedServer struct {
	connCh chan net.Conn
}

func NewHijackedServer(handler http.Handler) *HijackedServer {
	s := &HijackedServer{
		connCh: make(chan net.Conn),
	}
	go http.Serve(s, handler)
	return s
}

func (s *HijackedServer) Accept() (net.Conn, error) {
	c, ok := <-s.connCh
	if ok {
		return c, nil
	}
	return nil, errors.New("closed")
}

func (s *HijackedServer) Close() error {
	close(s.connCh)
	return nil
}

func (s *HijackedServer) Addr() net.Addr {
	return nil
}

func (s *HijackedServer) HandleConn(c net.Conn) {
	s.connCh <- c
}

func NewUnavailableServer() *HijackedServer {
	return NewHijackedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "0 proxy nolvs", http.StatusServiceUnavailable)
	}))
}
