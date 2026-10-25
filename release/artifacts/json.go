package artifacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func shape(d *json.Decoder, typ reflect.Type) error {
	token, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON token")
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return errors.New("expected JSON object")
		}
		known := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			known[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid JSON member")
			}
			name, ok := key.(string)
			child, exists := known[name]
			if !ok || !exists || seen[name] {
				return errors.New("unknown, duplicate or case-aliased JSON member")
			}
			seen[name] = true
			if err := shape(d, child); err != nil {
				return err
			}
		}
		if len(seen) != len(known) {
			return errors.New("missing required JSON member")
		}
		if _, err = d.Token(); err != nil {
			return errors.New("invalid object ending")
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return errors.New("expected a non-null JSON array")
		}
		count := 0
		for d.More() {
			count++
			if count > MaxFiles {
				return errors.New("JSON array exceeds limit")
			}
			if err := shape(d, typ.Elem()); err != nil {
				return err
			}
		}
		if _, err = d.Token(); err != nil {
			return errors.New("invalid array ending")
		}
	case reflect.String:
		value, ok := token.(string)
		if !ok || len(value) > 512 {
			return errors.New("invalid or oversized JSON string")
		}
	case reflect.Int, reflect.Int64:
		if _, ok := token.(json.Number); !ok {
			return errors.New("expected JSON integer")
		}
	default:
		return errors.New("unsupported JSON shape")
	}
	return nil
}

func decode(raw []byte, result any) error {
	if len(raw) == 0 || len(raw) > MaxDocumentBytes || !utf8.Valid(raw) {
		return errors.New("document exceeds size or encoding limits")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := shape(d, reflect.TypeOf(result).Elem()); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(result); err != nil {
		return errors.New("invalid typed JSON document")
	}
	return nil
}
