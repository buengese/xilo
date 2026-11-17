package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stubbedev/xilo/internal/api"
	"github.com/stubbedev/xilo/internal/config"
	"github.com/stubbedev/xilo/internal/store"
)

// TestStorageQuotaReadOnly pins over-quota behavior: pushes 403, pulls keep
// working, data is never deleted.
func TestStorageQuotaReadOnly(t *testing.T) {
	_, db, ts := newTestServer(t, true)
	db.CreateCache("default", "q", true, 40)

	// Tiny plan: 1 byte of logical storage.
	plan, err := db.CreatePlan(&store.Plan{Name: "tiny", MaxStorage: 1})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := db.GetAccount("default")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetAccountPlan(acc.ID, plan.ID); err != nil {
		t.Fatal(err)
	}

	// First push: under quota (0 < 1), lands.
	data := []byte("some data that will exceed one byte")
	pushFake(t, ts, "q", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data, "")

	// Now logical bytes >= 1: path registration is rejected (chunk uploads
	// aren't individually gated; the path gate is what admits data).
	more := []byte("more")
	ch, narHash, narSize := fakeNar(more)
	r := put(t, ts, "/c/default/q/api/chunk/"+ch, more, "")
	r.Body.Close()
	body, _ := json.Marshal(api.PathReq{
		StorePath: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-more",
		NarHash:   narHash, NarSize: narSize, Chunks: []string{ch},
	})
	if r := put(t, ts, "/c/default/q/api/path", body, ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("over-quota put-path → %d want 403", r.StatusCode)
	}

	// Pull still works.
	resp, _ := http.Get(ts.URL + "/c/default/q/nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("over-quota pull → %d want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestRetentionCeiling pins the plan clamp: a cache with no retention gets
// the plan ceiling applied by the sweep.
func TestRetentionCeiling(t *testing.T) {
	s, db, ts := newTestServer(t, true)
	db.CreateCache("default", "r", true, 40)
	data := []byte("old path data")
	pushFake(t, ts, "r", "cccccccccccccccccccccccccccccccc", data, "")

	// Backdate the path's accessed time far past any ceiling.
	c, _ := db.GetCache(context.Background(), "default", "r")
	// minAge is hugely negative so the guard (now-accessed < minAge) never
	// short-circuits a backwards stamp.
	db.TouchPath(c.ID, "cccccccccccccccccccccccccccccccc", time.Now().Add(-48*time.Hour).Unix(), -1<<62)

	// Plan ceiling: 1h retention.
	plan, err := db.CreatePlan(&store.Plan{Name: "short", MaxRetention: 3600})
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := db.GetAccount("default")
	if err := db.SetAccountPlan(acc.ID, plan.ID); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.runGC(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetPath(context.Background(), c.ID, "cccccccccccccccccccccccccccccccc"); err == nil {
		t.Fatal("path older than the plan ceiling survived the sweep")
	}
}

// TestEgressRollup pins metering: serving a NAR lands in the monthly rollup
// after a flush.
func TestEgressRollup(t *testing.T) {
	s, db, ts := newTestServer(t, true)
	db.CreateCache("default", "e", true, 40)
	data := []byte("bytes that leave the building")
	pushFake(t, ts, "e", "dddddddddddddddddddddddddddddddd", data, "")

	resp, _ := http.Get(ts.URL + "/c/default/e/nar/dddddddddddddddddddddddddddddddd.nar")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull → %d", resp.StatusCode)
	}
	resp.Body.Close()

	s.flushEgress()
	acc, _ := db.GetAccount("default")
	month := time.Now().UTC().Format("2006-01")
	if got := db.AccountEgress(acc.ID, month); got != int64(len(data)) {
		t.Fatalf("egress = %d want %d", got, len(data))
	}
}

// TestStorageQuotaFailsClosed pins what happens when an account's usage cannot
// be computed: pushes are refused, not waved through as if there were no cap.
// Two NarSizes at MaxInt64 (rows that predate the put-path ceiling) overflow
// SUM(nar_size), which used to read as "no limit" and lift the quota for good.
func TestStorageQuotaFailsClosed(t *testing.T) {
	_, db, ts := newTestServer(t, true)
	c, err := db.CreateCache("default", "q", true, 40)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := db.CreatePlan(&store.Plan{Name: "big", MaxStorage: 1 << 62})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := db.GetAccount("default")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetAccountPlan(acc.ID, plan.ID); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		if err := db.PutPath(c.ID, h, &store.Path{
			StorePath: "/nix/store/" + h + "-huge", NarHash: "sha256:" + strings.Repeat("0", 52),
			NarSize: math.MaxInt64,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.AccountLogicalBytes(acc.ID); err == nil {
		t.Fatal("precondition: the usage sum was expected to overflow")
	}

	body, _ := json.Marshal(api.MissingReq{Hashes: []string{"cccccccccccccccccccccccccccccccc"}})
	resp, err := http.Post(ts.URL+"/c/default/q/api/get-missing-paths", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(msg), "Could not check storage usage") {
		t.Fatalf("get-missing-paths with unreadable usage → %d %q, want 403 + quota message", resp.StatusCode, msg)
	}
}

// TestPutPathNarSizeCeiling pins the per-path NarSize ceiling that keeps the
// quota sum from overflowing. It runs with verification off, the one setting
// where the claimed size is never checked against the bytes, so the ceiling is
// the only thing deciding.
func TestPutPathNarSizeCeiling(t *testing.T) {
	_, db, ts := newTestServerCfg(t, func(c *config.Config) { c.Security.SkipUploadVerify = true })
	db.CreateCache("default", "c", true, 40)
	data := []byte("whatever")
	ch, _, _ := fakeNar(data)
	put(t, ts, "/c/default/c/api/chunk/"+ch, data, "").Body.Close()

	for _, tc := range []struct {
		hash string
		size uint64
		want int
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", maxNarSize, http.StatusOK},
		{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", maxNarSize + 1, http.StatusBadRequest},
	} {
		body, _ := json.Marshal(api.PathReq{
			StorePath: "/nix/store/" + tc.hash + "-x",
			NarHash:   "sha256:" + strings.Repeat("0", 52),
			NarSize:   tc.size, Chunks: []string{ch},
		})
		if r := put(t, ts, "/c/default/c/api/path", body, ""); r.StatusCode != tc.want {
			t.Errorf("narSize %d → %d want %d", tc.size, r.StatusCode, tc.want)
		}
	}
}
