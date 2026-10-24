package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Walk against the declared Go shape before decoding. encoding/json otherwise
// accepts duplicate members and case aliases, even with DisallowUnknownFields.
func keys(d *json.Decoder, t reflect.Type) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch t.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return errors.New("expected an object")
		}
		known := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			known[tag] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := k.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			child, ok := known[name]
			if !ok || seen[name] {
				return fmt.Errorf("unknown or duplicate object key %q", name)
			}
			seen[name] = true
			if err := keys(d, child); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case reflect.Slice:
		if token == nil {
			return nil
		}
		if token != json.Delim('[') {
			return errors.New("expected an array")
		}
		count := 0
		for d.More() {
			count++
			if count > MaxEntries {
				return errors.New("array exceeds entry limit")
			}
			if err := keys(d, t.Elem()); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		if _, ok := token.(json.Delim); ok {
			return errors.New("unexpected nested object or array")
		}
		switch t.Kind() {
		case reflect.String:
			if _, ok := token.(string); !ok {
				return errors.New("expected a string")
			}
		case reflect.Bool:
			if _, ok := token.(bool); !ok {
				return errors.New("expected a boolean")
			}
		case reflect.Int, reflect.Int64, reflect.Uint32, reflect.Uint64:
			if _, ok := token.(json.Number); !ok {
				return errors.New("expected an integer")
			}
		}
		return nil
	}
}

func decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes {
		return errors.New("document exceeds its size bounds")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := keys(d, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing document data")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func DecodeManifest(raw []byte) (Manifest, error) {
	var m Manifest
	err := decode(raw, &m)
	if err == nil {
		err = m.validate()
	}
	if err == nil {
		_, err = m.Canonical()
	}
	return m, err
}
func DecodePolicy(raw []byte) (Policy, error) {
	var p Policy
	err := decode(raw, &p)
	if err == nil {
		err = p.Validate()
	}
	if err == nil {
		_, err = p.Canonical()
	}
	return p, err
}
