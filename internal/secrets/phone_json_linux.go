package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

var invalidApprovalMessage = errors.New("invalid_request")

func hasPhoneBatchCapability(capabilities []string) bool {
	for _, c := range capabilities {
		if c == phoneBatchCapability {
			return true
		}
	}
	return false
}

// encoding/json otherwise accepts repeated object keys and replaces malformed
// UTF-8/surrogate escapes. Neither is accepted at this credential boundary.
func decodeApprovalMessage(data []byte, msg *approvalMessage) error {
	if !utf8.Valid(data) || !validJSONSurrogates(data) {
		return invalidApprovalMessage
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if uniqueJSONValue(decoder, 0) != nil {
		return invalidApprovalMessage
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalidApprovalMessage
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(msg) != nil {
		return invalidApprovalMessage
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(data, &keys) != nil {
		return invalidApprovalMessage
	}
	defer func() {
		for _, raw := range keys {
			clear(raw)
		}
	}()
	_, value := keys["value"]
	_, values := keys["values"]
	_, capabilities := keys["capabilities"]
	if capabilities && msg.Method != "list" {
		return invalidApprovalMessage
	}
	switch msg.Method {
	case "release":
		if !value || values {
			return invalidApprovalMessage
		}
	case "release_batch":
		if value || !values || msg.Values == nil {
			return invalidApprovalMessage
		}
	default:
		if value || values {
			return invalidApprovalMessage
		}
	}
	return nil
}

func uniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return invalidApprovalMessage
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || keys[key] {
				return invalidApprovalMessage
			}
			// Use exact schema names; case aliases such as id/ID must not
			// become two spellings of the same field during struct decoding.
			if depth == 0 {
				switch key {
				case "version", "id", "method", "request_id", "value", "values", "capabilities":
				default:
					return invalidApprovalMessage
				}
			} else if depth == 2 {
				if key != "id" && key != "value" {
					return invalidApprovalMessage
				}
			} else {
				return invalidApprovalMessage
			}
			keys[key] = true
			if err := uniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return invalidApprovalMessage
	}
	_, err = decoder.Token()
	return err
}

func validJSONSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		r, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if r >= 0xdc00 && r <= 0xdfff {
			return false
		}
		if r >= 0xd800 && r <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
