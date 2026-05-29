package storage

import "fmt"

type Type string

var (
	MemoryType Type = "memory"
	RedisType  Type = "redis"
)

func ParseType(s string) (Type, error) {
	switch s {
	case "memory":
		return MemoryType, nil
	case "redis":
		return RedisType, nil
	default:
		return "", fmt.Errorf("invalid storage type: %q", s)
	}
}
