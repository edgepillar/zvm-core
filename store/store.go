// Package store keeps what the derivation node learns that op-geth does not
// hold: which momentum made which L2 block, what became of every NoM message,
// and the chunks a later assemble may name.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	_ "modernc.org/sqlite"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

type DB struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS momentums (
	height     INTEGER PRIMARY KEY,
	hash       TEXT    NOT NULL,
	timestamp  INTEGER NOT NULL,
	l2_number  INTEGER NOT NULL,
	l2_hash    TEXT    NOT NULL,
	txs        INTEGER NOT NULL,
	messages   INTEGER NOT NULL,
	dropped    INTEGER NOT NULL,
	nom_blocks INTEGER NOT NULL,
	zvm_bytes  INTEGER NOT NULL,
	zvm_plasma INTEGER NOT NULL,
	gas_used   INTEGER NOT NULL,
	build_ms   INTEGER NOT NULL,
	attempts   INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS momentums_l2 ON momentums(l2_number);
CREATE TABLE IF NOT EXISTS messages (
	nom_hash TEXT PRIMARY KEY,
	momentum INTEGER NOT NULL,
	idx      INTEGER NOT NULL,
	author   TEXT    NOT NULL,
	kind     TEXT    NOT NULL,
	status   TEXT    NOT NULL,
	reason   TEXT,
	bytes    INTEGER NOT NULL,
	plasma   INTEGER NOT NULL,
	token    TEXT,
	amount   TEXT,
	txs      TEXT,
	dropped  TEXT
);
CREATE INDEX IF NOT EXISTS messages_author ON messages(author, momentum);
CREATE INDEX IF NOT EXISTS messages_momentum ON messages(momentum, idx);
CREATE INDEX IF NOT EXISTS messages_kind ON messages(kind, momentum);
CREATE TABLE IF NOT EXISTS tx_origin (
	tx_hash  TEXT PRIMARY KEY,
	nom_hash TEXT NOT NULL,
	lane     TEXT NOT NULL,
	momentum INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tx_origin_momentum ON tx_origin(momentum);
CREATE TABLE IF NOT EXISTS drops (
	tx_hash  TEXT    NOT NULL,
	momentum INTEGER NOT NULL,
	nom_hash TEXT    NOT NULL,
	reason   TEXT,
	PRIMARY KEY (tx_hash, momentum)
);
CREATE INDEX IF NOT EXISTS drops_momentum ON drops(momentum);
CREATE TABLE IF NOT EXISTS chunks (
	hash     TEXT PRIMARY KEY,
	author   TEXT    NOT NULL,
	momentum INTEGER NOT NULL,
	data     BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS chunks_momentum ON chunks(momentum);
-- Mandatory messages a block had no room for (docs/HALT.md, path 6), kept until
-- a later block applies them. Like chunks they are derivation input, so a
-- rewind forgets what the rewound momentums queued or released.
CREATE TABLE IF NOT EXISTS deferred (
	nom_hash    TEXT PRIMARY KEY,
	momentum    INTEGER NOT NULL,
	idx         INTEGER NOT NULL,
	block       TEXT    NOT NULL,
	released_at INTEGER
);
CREATE INDEX IF NOT EXISTS deferred_queue ON deferred(released_at, momentum, idx);
`

func Open(path string) (*DB, error) {
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating %s: %w", path, err)
	}
	// Columns added after the first release. SQLite has no "ADD COLUMN IF NOT
	// EXISTS", and this store is small enough that re-deriving would also be an
	// option — but a node that has one should not have to.
	for _, col := range []string{
		"ALTER TABLE messages ADD COLUMN burned TEXT",
		"ALTER TABLE messages ADD COLUMN burn_token TEXT",
		"ALTER TABLE messages ADD COLUMN fee_gas INTEGER",
		"ALTER TABLE messages ADD COLUMN fee_price INTEGER",
		"ALTER TABLE messages ADD COLUMN boost TEXT",
		"ALTER TABLE messages ADD COLUMN boost_gas INTEGER",
		// From the gas fork a chunk may be assembled once. The momentum that
		// spent it is kept rather than a flag, so a rewind can release it.
		"ALTER TABLE chunks ADD COLUMN consumed_at INTEGER",
		"ALTER TABLE messages ADD COLUMN deferred_from INTEGER",
		// The fusion price the momentum set for the next, in units of
		// PriceScaleFactor. NULL on rows written before it was kept; the API
		// fills those in from NoM the first time they are asked for.
		"ALTER TABLE momentums ADD COLUMN fusion_price INTEGER",
	} {
		if _, err := db.Exec(col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrating %s: %w", path, err)
		}
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error { return d.db.Close() }

// SQL exposes the handle to packages that keep their own tables alongside.
func (d *DB) SQL() *sql.DB { return d.db }

// Head is the last derived momentum.
type Head struct {
	Height   uint64
	Hash     znn.Hash
	L2Number uint64
	L2Hash   common.Hash
}

// Head returns the last derived momentum, or nil if nothing is derived yet.
func (d *DB) Head() (*Head, error) {
	return d.headWhere("ORDER BY height DESC LIMIT 1")
}

// MomentumHead returns the derived row for a momentum height, or nil.
func (d *DB) MomentumHead(height uint64) (*Head, error) {
	return d.headWhere("WHERE height = ?", height)
}

func (d *DB) headWhere(clause string, args ...any) (*Head, error) {
	var h Head
	var hash, l2hash string
	err := d.db.QueryRow("SELECT height, hash, l2_number, l2_hash FROM momentums "+clause, args...).
		Scan(&h.Height, &hash, &h.L2Number, &l2hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if h.Hash, err = znn.ParseHash(hash); err != nil {
		return nil, err
	}
	h.L2Hash = common.HexToHash(l2hash)
	return &h, nil
}

// Derived is one momentum's derivation result.
type Derived struct {
	Momentum  *znn.Momentum
	NomBlocks int
	L2Number  uint64
	L2Hash    common.Hash
	GasUsed   uint64
	BuildMS   int64
	Attempts  int
	Plan      *derive.Plan
}

func (d *DB) RecordDerived(r *Derived, chunkTTL uint64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	m := r.Momentum
	var zvmBytes, zvmPlasma, dropped int64
	for _, msg := range r.Plan.Messages {
		zvmBytes += int64(msg.Bytes)
		zvmPlasma += int64(msg.Plasma)
		dropped += int64(len(msg.Dropped))
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO momentums
		(height, hash, timestamp, l2_number, l2_hash, txs, messages, dropped, nom_blocks, zvm_bytes, zvm_plasma, gas_used, build_ms, attempts, fusion_price)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		m.Height, m.Hash.String(), m.Timestamp, r.L2Number, r.L2Hash.Hex(), len(r.Plan.Txs), len(r.Plan.Messages),
		dropped, r.NomBlocks, zvmBytes, zvmPlasma, r.GasUsed, r.BuildMS, r.Attempts, m.FusionPrice()); err != nil {
		return err
	}
	for _, msg := range r.Plan.Messages {
		txs, _ := json.Marshal(msg.Txs)
		drops, _ := json.Marshal(msg.Dropped)
		if _, err := tx.Exec(`INSERT OR REPLACE INTO messages
			(nom_hash, momentum, idx, author, kind, status, reason, bytes, plasma, token, amount, txs, dropped,
			 burned, burn_token, fee_gas, fee_price, boost, boost_gas, deferred_from)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			msg.NomHash.String(), m.Height, msg.Index, msg.Author.String(), msg.Kind, msg.Status, msg.Reason,
			msg.Bytes, msg.Plasma, msg.Token, msg.Amount, string(txs), string(drops),
			msg.Burned, msg.BurnToken, msg.FeeGas, msg.FeePrice, msg.Boost, msg.BoostGas,
			sql.NullInt64{Int64: int64(msg.DeferredFrom), Valid: msg.DeferredFrom != 0}); err != nil {
			return err
		}
		for _, drop := range msg.Dropped {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO drops (tx_hash, momentum, nom_hash, reason) VALUES (?,?,?,?)`,
				drop.Hash.Hex(), m.Height, msg.NomHash.String(), drop.Reason); err != nil {
				return err
			}
		}
	}
	for _, t := range r.Plan.Txs {
		origin := m.Hash.String()
		if t.Message >= 0 {
			origin = r.Plan.Messages[t.Message].NomHash.String()
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO tx_origin (tx_hash, nom_hash, lane, momentum) VALUES (?,?,?,?)`,
			t.Tx.Hash().Hex(), origin, t.Lane, m.Height); err != nil {
			return err
		}
	}
	for _, c := range r.Plan.NewChunks {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO chunks (hash, author, momentum, data) VALUES (?,?,?,?)`,
			c.Hash.String(), c.Author.String(), c.Height, c.Data); err != nil {
			return err
		}
	}
	for _, h := range r.Plan.UsedChunks {
		if _, err := tx.Exec(`UPDATE chunks SET consumed_at = ? WHERE hash = ? AND consumed_at IS NULL`,
			m.Height, h.String()); err != nil {
			return err
		}
	}
	for _, q := range r.Plan.Deferred {
		raw, err := json.Marshal(q.Block)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO deferred (nom_hash, momentum, idx, block) VALUES (?,?,?,?)`,
			q.Block.Hash.String(), q.From, q.Index, string(raw)); err != nil {
			return err
		}
	}
	for _, h := range r.Plan.Released {
		if _, err := tx.Exec(`UPDATE deferred SET released_at = ? WHERE nom_hash = ? AND released_at IS NULL`,
			m.Height, h.String()); err != nil {
			return err
		}
	}
	if chunkTTL > 0 && m.Height%1000 == 0 && m.Height > chunkTTL {
		if _, err := tx.Exec(`DELETE FROM chunks WHERE momentum < ?`, m.Height-chunkTTL); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RewindTo forgets everything derived from momentums above height.
func (d *DB) RewindTo(height uint64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		"DELETE FROM momentums WHERE height > ?",
		"DELETE FROM messages WHERE momentum > ?",
		"DELETE FROM tx_origin WHERE momentum > ?",
		"DELETE FROM drops WHERE momentum > ?",
		"DELETE FROM chunks WHERE momentum > ?",
		// A chunk spent by a momentum that is being re-derived is unspent again.
		"UPDATE chunks SET consumed_at = NULL WHERE consumed_at > ?",
		// The deferral queue, the same way: forget what was queued above the
		// height, and put back what was released above it.
		"DELETE FROM deferred WHERE momentum > ?",
		"UPDATE deferred SET released_at = NULL WHERE released_at > ?",
	} {
		if _, err := tx.Exec(stmt, height); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Chunk implements derive.ChunkSource.
func (d *DB) Chunk(hash znn.Hash) (*derive.Chunk, bool, error) {
	var author string
	var height uint64
	var data []byte
	var consumedAt sql.NullInt64
	err := d.db.QueryRow("SELECT author, momentum, data, consumed_at FROM chunks WHERE hash = ?", hash.String()).
		Scan(&author, &height, &data, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read chunk %s: %w", hash, err)
	}
	a, err := znn.ParseAddress(author)
	if err != nil {
		return nil, false, fmt.Errorf("decode chunk %s author: %w", hash, err)
	}
	return &derive.Chunk{Hash: hash, Author: a, Height: height, Data: data, Consumed: consumedAt.Valid}, true, nil
}

// Deferred implements derive.DeferralSource: the mandatory messages momentums
// below height queued and none has released, oldest first.
func (d *DB) Deferred(before uint64) ([]*derive.DeferredBlock, error) {
	rows, err := d.db.Query(`SELECT momentum, idx, block FROM deferred
		WHERE released_at IS NULL AND momentum < ? ORDER BY momentum, idx`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*derive.DeferredBlock
	for rows.Next() {
		q := &derive.DeferredBlock{}
		var raw string
		if err := rows.Scan(&q.From, &q.Index, &raw); err != nil {
			return nil, err
		}
		q.Block = new(znn.AccountBlock)
		if err := json.Unmarshal([]byte(raw), q.Block); err != nil {
			return nil, fmt.Errorf("deferred message from momentum %d: %w", q.From, err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// Placeholders builds "?,?,?" for IN clauses.
func Placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}
