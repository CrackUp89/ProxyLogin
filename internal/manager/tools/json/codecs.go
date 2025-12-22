package json

import (
	"encoding/json"
	"net/http"
)

type EncodeJSONError struct {
	encodingError error
}

func (e EncodeJSONError) Error() string {
	return e.encodingError.Error()
}

func EncodeJSON[T any](w http.ResponseWriter, status int, v T) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return &EncodeJSONError{encodingError: err}
	}
	return nil
}

type DecodeJSONError struct {
	decodingError error
}

func (e DecodeJSONError) Error() string {
	return e.decodingError.Error()
}

func DecodeJSON[T any](r *http.Request) (T, error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return v, &DecodeJSONError{decodingError: err}
	}
	return v, nil
}
