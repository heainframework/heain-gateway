package replica

import (
	"path/filepath"
	"testing"
)

type mem map[string][]byte

func (m mem) ApplyRaw(k string, v []byte) error {
	if v == nil {
		delete(m, k)
	} else {
		m[k] = v
	}
	return nil
}

func open(t *testing.T, self string) (*Log, mem) {
	l, err := Open(filepath.Join(t.TempDir(), self+".db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	m := mem{}
	l.Register("account", m)
	return l, m
}

// pull copies everything new in from's log into to.
func pull(t *testing.T, to *Log, from *Log, peer string) int {
	ep, _, cs, err := from.Changes(to.Cursor(peer, from.Epoch()), 1000)
	if err != nil {
		t.Fatal(err)
	}
	n, err := to.Apply(peer, ep, cs)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReplicaConverges(t *testing.T) {
	g, gm := open(t, "g1")
	w, wm := open(t, "w1")
	gm["k1"] = []byte("v1")
	_ = g.Record("account", "k1", []byte("v1"))
	if pull(t, w, g, "g1") != 1 || string(wm["k1"]) != "v1" {
		t.Fatal("w must get g's write")
	}
	if pull(t, w, g, "g1") != 0 {
		t.Fatal("the cursor must move: nothing new the second time")
	}
	// both write k1 while cut off: the later write wins on both
	gm["k1"] = []byte("g-late")
	wm["k1"] = []byte("w-early")
	_ = w.Record("account", "k1", []byte("w-early"))
	_ = g.Record("account", "k1", []byte("g-late"))
	pull(t, w, g, "g1")
	pull(t, g, w, "w1")
	if string(gm["k1"]) != "g-late" || string(wm["k1"]) != "g-late" {
		t.Fatalf("last writer wins: g=%s w=%s", gm["k1"], wm["k1"])
	}
	// a delete replicates
	delete(wm, "k1")
	_ = w.Record("account", "k1", nil)
	pull(t, g, w, "w1")
	if _, ok := gm["k1"]; ok {
		t.Fatal("delete must replicate")
	}
	// a node that joins later gets everything, also what came from others (relay)
	x, xm := open(t, "x1")
	_ = w.Record("account", "k2", []byte("from-w"))
	wm["k2"] = []byte("from-w")
	pull(t, g, w, "w1")
	pull(t, x, g, "g1")
	if string(xm["k2"]) != "from-w" {
		t.Fatal("a late node gets relayed changes")
	}
	if _, ok := xm["k1"]; ok {
		t.Fatal("and the delete")
	}
	// compaction keeps only the latest change of each record
	before, _, _ := func() (int, int, error) { _, h, cs, err := g.Changes(0, 1000); return len(cs), int(h), err }()
	if n, err := g.Compact(); err != nil || n == 0 {
		t.Fatalf("compact: %d %v", n, err)
	}
	_, _, cs, _ := g.Changes(0, 1000)
	if len(cs) >= before {
		t.Fatal("compaction must drop replaced changes")
	}
	y, ym := open(t, "y1")
	pull(t, y, g, "g1")
	if string(ym["k2"]) != "from-w" || ym["k1"] != nil {
		t.Fatal("a node reading a compacted log still gets every record's latest state")
	}
	// an unknown store is refused
	if _, err := x.Apply("g1", g.Epoch(), []Change{{Seq: 99, Store: "nope", Key: "k", TS: 1}}); err == nil {
		t.Fatal("unknown store accepted")
	}
	// a peer whose log was recreated is read from the start
	if x.Cursor("g1", "another-epoch") != 0 {
		t.Fatal("a new epoch must reset the cursor")
	}
}
