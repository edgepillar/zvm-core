package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"modernc.org/sqlite"
)

// These fixtures use unsigned deposit data and synthetic addresses. SQL refusal
// and process exit are real; no engine, wallet, signer or public RPC is used.
func n04Derived(height uint64) *Derived {
	m := &znn.Momentum{Height: height, Hash: znn.Hash{0: byte(height)}, Timestamp: 1800000000 + height}
	at := common.Address{19: 9}
	tx := types.NewTx(&types.DepositTx{SourceHash: common.Hash{0: byte(height)}, From: at, To: &at, Value: new(big.Int), Gas: 30000})
	block := &znn.AccountBlock{Version: 1, ChainIdentifier: 70, Height: height, BlockType: znn.BlockTypeUserSend,
		Address: znn.Address{19: 8}, ToAddress: znn.Address{19: 9}, TokenStandard: znn.ZNN, Amount: znn.BigIntFromUint64(1)}
	block.Hash = block.ComputeHash()
	message := &derive.Message{NomHash: znn.Hash{1: byte(height)}, Author: block.Address, Index: 1, Kind: "fixture", Status: "applied",
		Txs: []common.Hash{tx.Hash()}, Dropped: []derive.TxDrop{{Hash: common.Hash{2: byte(height)}, Reason: "fixture"}}}
	plan := &derive.Plan{Momentum: m, Messages: []*derive.Message{message},
		Txs:       []*derive.PlannedTx{{Tx: tx, Lane: "native", Message: 0, Mandatory: true}},
		NewChunks: []*derive.Chunk{{Hash: znn.Hash{3: byte(height)}, Author: block.Address, Height: height, Data: []byte{byte(height)}}},
		Deferred:  []*derive.DeferredBlock{{Block: block, From: height, Index: 1}}}
	if height == 11 {
		plan.UsedChunks = []znn.Hash{{3: 10}}
		plan.Released = []znn.Hash{n04Derived(10).Plan.Deferred[0].Block.Hash}
	}
	return &Derived{Momentum: m, L2Number: height - 9, L2Hash: common.Hash{4: byte(height)}, Attempts: 1, Plan: plan}
}

func n04Open(t *testing.T, path string) *DB {
	t.Helper()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func n04Record(t *testing.T, db *DB, height uint64) {
	t.Helper()
	if err := db.RecordDerived(n04Derived(height), 0); err != nil {
		t.Fatal(err)
	}
}

// Compare every persisted value, including chunk/deferred consumption and all
// origin/message metadata, rather than checking only a head or row count.
func n04State(t *testing.T, db *DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"momentums", "messages", "tx_origin", "drops", "chunks", "deferred"} {
		rows, err := db.SQL().Query("SELECT * FROM " + table + " ORDER BY 1,2")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		values := [][]any{}
		for rows.Next() {
			row := make([]any, len(columns))
			pointers := make([]any, len(row))
			for i := range row {
				pointers[i] = &row[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			for i, value := range row {
				if raw, ok := value.([]byte); ok {
					row[i] = append([]byte(nil), raw...)
				}
			}
			values = append(values, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
		raw, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		out[table] = string(raw)
	}
	var integrity string
	if err := db.SQL().QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("SQLite integrity after recovery: %q, %v", integrity, err)
	}
	return out
}

func n04Same(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		for table, value := range want {
			if got[table] != value {
				t.Errorf("recovered %s differs from the complete reference state", table)
			}
		}
		t.FailNow()
	}
}

func TestRecordDerivedRefusalRollsBackEveryTableAndReplaysAfterRestore(t *testing.T) {
	for _, boundary := range []string{"INSERT ON momentums", "INSERT ON messages", "INSERT ON drops", "INSERT ON tx_origin", "INSERT ON chunks", "UPDATE OF consumed_at ON chunks", "INSERT ON deferred", "UPDATE OF released_at ON deferred"} {
		t.Run(boundary, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "refusal.db")
			db := n04Open(t, path)
			n04Record(t, db, 10)
			before := n04State(t, db)
			if _, err := db.SQL().Exec("CREATE TRIGGER n04_refusal AFTER " + boundary + " BEGIN SELECT RAISE(ABORT,'n04_refusal'); END"); err != nil {
				t.Fatal(err)
			}
			if err := db.RecordDerived(n04Derived(11), 0); err == nil || !strings.Contains(err.Error(), "n04_refusal") {
				t.Fatalf("declared transaction refusal was not reached: %v", err)
			}
			n04Same(t, n04State(t, db), before)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = n04Open(t, path)
			n04Same(t, n04State(t, db), before)
			if _, err := db.SQL().Exec("DROP TRIGGER n04_refusal"); err != nil {
				t.Fatal(err)
			}
			n04Record(t, db, 11)
			reference := n04Open(t, filepath.Join(t.TempDir(), "reference.db"))
			n04Record(t, reference, 10)
			n04Record(t, reference, 11)
			n04Same(t, n04State(t, db), n04State(t, reference))
		})
	}
}

func TestRewindRefusalPreservesOriginalStateAndRestoresEveryTable(t *testing.T) {
	for _, boundary := range []string{"DELETE ON momentums", "DELETE ON messages", "DELETE ON tx_origin", "DELETE ON drops", "DELETE ON chunks", "UPDATE OF consumed_at ON chunks", "DELETE ON deferred", "UPDATE OF released_at ON deferred"} {
		t.Run(boundary, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rewind.db")
			db := n04Open(t, path)
			n04Record(t, db, 10)
			n04Record(t, db, 11)
			before := n04State(t, db)
			if _, err := db.SQL().Exec("CREATE TRIGGER n04_refusal AFTER " + boundary + " BEGIN SELECT RAISE(ABORT,'n04_refusal'); END"); err != nil {
				t.Fatal(err)
			}
			if err := db.RewindTo(10); err == nil || !strings.Contains(err.Error(), "n04_refusal") {
				t.Fatalf("declared rewind refusal was not reached: %v", err)
			}
			n04Same(t, n04State(t, db), before)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = n04Open(t, path)
			n04Same(t, n04State(t, db), before)
			if _, err := db.SQL().Exec("DROP TRIGGER n04_refusal"); err != nil {
				t.Fatal(err)
			}
			if err := db.RewindTo(10); err != nil {
				t.Fatal(err)
			}
			reference := n04Open(t, filepath.Join(t.TempDir(), "reference.db"))
			n04Record(t, reference, 10)
			n04Same(t, n04State(t, db), n04State(t, reference))
		})
	}
}

func n04CrashWorker(t *testing.T) {
	t.Helper()
	path, phase := os.Getenv("ZVM_N04_DB"), os.Getenv("ZVM_N04_PHASE")
	if !filepath.IsAbs(path) || filepath.Base(path) != "crash.db" {
		t.Fatal("owned fixture path required")
	}
	if err := sqlite.RegisterScalarFunction("n04_exit", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		os.Exit(93) // Deliberate process termination; no Go/SQLite cleanup runs.
		return nil, fmt.Errorf("unreachable")
	}); err != nil {
		t.Fatal(err)
	}
	db := n04Open(t, path)
	switch phase {
	case "record-uncommitted", "rewind-uncommitted":
		verb := "INSERT"
		if phase == "rewind-uncommitted" {
			verb = "DELETE"
		}
		if _, err := db.SQL().Exec("CREATE TRIGGER n04_crash AFTER " + verb + " ON deferred BEGIN SELECT n04_exit(); END"); err != nil {
			t.Fatal(err)
		}
	case "record-committed", "rewind-committed":
	default:
		t.Fatal("unknown declared crash phase")
	}
	if strings.HasPrefix(phase, "record-") {
		n04Record(t, db, 11)
	} else if err := db.RewindTo(10); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(phase, "-committed") {
		os.Exit(93)
	}
	t.Fatal("transaction crash point was not reached")
}

// Abrupt process exit is distinct from a clean close/reopen and from a machine
// power loss. The latter, actual engines and canonical serving remain unproven.
func TestStoreCrashProcess(t *testing.T) {
	if os.Getenv("ZVM_N04_WORKER") == "1" {
		n04CrashWorker(t)
		return
	}
	for _, phase := range []string{"record-uncommitted", "record-committed", "rewind-uncommitted", "rewind-committed"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "crash.db")
			db := n04Open(t, path)
			n04Record(t, db, 10)
			if strings.HasPrefix(phase, "rewind-") {
				n04Record(t, db, 11)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStoreCrashProcess$", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "ZVM_N04_WORKER=1", "ZVM_N04_DB="+path, "ZVM_N04_PHASE="+phase)
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 93 || ctx.Err() != nil {
				t.Fatalf("declared worker exit was not observed: %v, %s", err, out)
			}
			t.Logf("observed owned worker %s exit 93 without cleanup", phase)
			db = n04Open(t, path)
			reference := n04Open(t, filepath.Join(t.TempDir(), "reference.db"))
			n04Record(t, reference, 10)
			if phase == "record-committed" || phase == "rewind-uncommitted" {
				n04Record(t, reference, 11)
			}
			n04Same(t, n04State(t, db), n04State(t, reference))
		})
	}
}
