package stateaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// The same exact-name boundary used by release/agreement inputs: duplicate
// members and case aliases cannot silently replace a policy or identity value.
func scanContextJSON(raw []byte, limit uint64) error {
	if len(raw) == 0 || uint64(len(raw)) > limit || !utf8.Valid(raw) {
		return errors.New("snapshot context document exceeds bounds")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if depth > 32 || tokens > 65536 {
			return errors.New("snapshot context JSON budget")
		}
		token, err := d.Token()
		if err != nil {
			return errors.New("invalid snapshot context JSON")
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' {
				return errors.New("invalid snapshot context delimiter")
			}
			seen := map[string]bool{}
			for d.More() {
				if delimiter == '{' {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errors.New("duplicate or invalid snapshot context key")
					}
					seen[name] = true
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
				return errors.New("invalid snapshot context end")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing snapshot context data")
	}
	return nil
}

func contextObject(raw []byte, limit uint64) (map[string]json.RawMessage, error) {
	if err := scanContextJSON(raw, limit); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, errors.New("snapshot context object required")
	}
	return object, nil
}

func requiredContextFields(object map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if len(object[name]) == 0 || bytes.Equal(bytes.TrimSpace(object[name]), []byte("null")) {
			return errors.New("missing snapshot context field")
		}
		for actual := range object {
			if strings.EqualFold(actual, name) && actual != name {
				return errors.New("aliased snapshot context field")
			}
		}
	}
	return nil
}

func contextShape(raw json.RawMessage, shape reflect.Type, limit uint64) error {
	if shape == reflect.TypeOf(hexutil.Bytes{}) {
		var value string
		if json.Unmarshal(raw, &value) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("hexadecimal snapshot header required")
		}
		return nil
	}
	switch shape.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil || len(object) != shape.NumField() {
			return errors.New("snapshot context fields must match the exact schema")
		}
		for i := 0; i < shape.NumField(); i++ {
			field := shape.Field(i)
			name := field.Tag.Get("json")
			if requiredContextFields(object, name) != nil {
				return errors.New("missing or aliased snapshot context field")
			}
			if err := contextShape(object[name], field.Type, limit); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > 4096 {
			return errors.New("bounded snapshot context array required")
		}
		for _, value := range values {
			if err := contextShape(value, shape.Elem(), limit); err != nil {
				return err
			}
		}
	default:
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("snapshot context field cannot be null")
		}
	}
	return nil
}

func decodeContextDocument(raw []byte, out any, limit uint64) error {
	if err := scanContextJSON(raw, limit); err != nil {
		return err
	}
	if err := contextShape(raw, reflect.TypeOf(out).Elem(), limit); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("snapshot context field type mismatch")
	}
	return nil
}

func DecodeSnapshotPolicy(raw []byte, limit uint64) (SnapshotPolicy, error) {
	var policy SnapshotPolicy
	if err := decodeContextDocument(raw, &policy, limit); err != nil {
		return SnapshotPolicy{}, err
	}
	if err := policy.validate(); err != nil {
		return SnapshotPolicy{}, err
	}
	return policy, nil
}

func DecodeSnapshot(raw []byte, limit uint64) (Snapshot, error) {
	var snapshot Snapshot
	if err := decodeContextDocument(raw, &snapshot, limit); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Schema != 1 || !contextDigest(snapshot.WitnessSHA256) || len(snapshot.SigningMessage) == 0 || len(snapshot.Headers) == 0 {
		return Snapshot{}, errors.New("snapshot fields unavailable")
	}
	return snapshot, nil
}

func DecodeCheckpoint(raw []byte, limit uint64) (Checkpoint, error) {
	var checkpoint Checkpoint
	if err := decodeContextDocument(raw, &checkpoint, limit); err != nil {
		return Checkpoint{}, err
	}
	if err := checkpoint.validate(); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}
