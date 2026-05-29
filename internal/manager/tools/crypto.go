package tools

import (
	"crypto/rand"
	"math/big"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var charsetLength = big.NewInt(int64(len(charset)))

func GenerateRandomString(length int) (string, error) {
	result := make([]byte, length)

	for i := range length {
		randomIndex, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}
