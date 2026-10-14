package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
	"github.com/angga-22/pqinv/internal/scan"
	"github.com/angga-22/pqinv/internal/serve"
)

func TestValidateServeFlags(t *testing.T) {
	if err := validateServeFlags(time.Hour, ":9465"); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}
	if err := validateServeFlags(time.Second, ":9465"); err == nil {
		t.Error("a one-second interval would hammer IdPs; must be rejected")
	}
	if err := validateServeFlags(time.Minute, ""); err == nil {
		t.Error("empty listen address must be rejected")
	}
}

type stubProbe struct{}

func (stubProbe) Name() string { return "tls" }
func (stubProbe) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	return []model.CryptoAsset{{Source: "tls", Location: target, Usage: model.UsageKeyExchange, Algorithm: "X25519MLKEM768"}}, nil
}

// End to end: runServe binds a real port, serves metrics, and stops
// cleanly on context cancel.
func TestRunServeServesAndShutsDown(t *testing.T) {
	c, err := classify.New()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // free it for ListenAndServe

	srv := &serve.Server{
		Runner:     &scan.Runner{Probes: map[string]probe.Probe{"tls": stubProbe{}}},
		Classifier: c,
		Targets:    []scan.Target{{Probe: "tls", Target: "a:443"}},
		Interval:   time.Hour,
		Version:    "test",
	}
	httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServe(ctx, srv, httpSrv, log.New(io.Discard, "", 0)) }()

	var body string
	for i := 0; i < 50; i++ {
		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			if strings.Contains(body, "pqinv_scans_total 1") {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, `pqinv_score{probe="tls",target="a:443"} 100`) {
		t.Errorf("metrics not served after first scan:\n%s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("runServe returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runServe did not shut down after cancel")
	}
}
