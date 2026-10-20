package main

import (
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func fingerprint(pemBytes []byte) (string, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return "", errors.New("not a PEM certificate")
	}
	sum := sha256.Sum256(b.Bytes)
	parts := make([]string, len(sum))
	for i, x := range sum {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":"), nil
}
