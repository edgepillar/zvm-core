package store

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func TestChunkReadDistinguishesAbsenceFromStorageAndDecodeErrors(t *testing.T) {
	for _, fixture := range []string{"missing", "valid", "bad author", "bad height", "missing table", "closed database"} {
		t.Run(fixture, func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "zvm.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			hash := znn.Hash{0: 7}
			author, height := any(znn.Address{19: 9}.String()), any(11)
			switch fixture {
			case "bad author":
				author = "invalid fixture address"
			case "bad height":
				height = "not a height"
			}
			if fixture == "valid" || fixture == "bad author" || fixture == "bad height" {
				if _, err := db.db.Exec("INSERT INTO chunks(hash,author,momentum,data,consumed_at) VALUES(?,?,?,?,?)", hash.String(), author, height, []byte{1, 2, 3}, 12); err != nil {
					t.Fatal(err)
				}
			}
			if fixture == "missing table" {
				if _, err := db.db.Exec("DROP TABLE chunks"); err != nil {
					t.Fatal(err)
				}
			}
			if fixture == "closed database" {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			chunk, found, err := db.Chunk(hash)
			switch fixture {
			case "missing":
				if chunk != nil || found || err != nil {
					t.Fatalf("genuine absence: chunk=%v found=%v err=%v", chunk, found, err)
				}
			case "valid":
				if err != nil || !found || chunk == nil || chunk.Hash != hash || chunk.Height != 11 || !chunk.Consumed || !bytes.Equal(chunk.Data, []byte{1, 2, 3}) || chunk.Author != (znn.Address{19: 9}) {
					t.Fatalf("valid stored chunk did not round-trip: chunk=%+v found=%v err=%v", chunk, found, err)
				}
			default:
				if chunk != nil || found || err == nil {
					t.Fatalf("storage/decode failure was reported as absence: chunk=%v found=%v err=%v", chunk, found, err)
				}
			}
		})
	}
}
