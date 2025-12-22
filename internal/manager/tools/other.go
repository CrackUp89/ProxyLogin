package tools

import "strings"

func ReverseMap[K comparable, V comparable](m map[K]V) map[V]K {
	n := make(map[V]K, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

const maxInt = int(^uint(0) >> 1)

type Stringable interface {
	String() string
}

func JoinStringable[T Stringable](elems []T, sep string) string {
	switch len(elems) {
	case 0:
		return ""
	case 1:
		return elems[0].String()
	}

	var n int
	if len(sep) > 0 {
		if len(sep) >= maxInt/(len(elems)-1) {
			panic("strings: Join output length overflow")
		}
		n += len(sep) * (len(elems) - 1)
	}
	for _, elem := range elems {
		str := elem.String()
		if len(str) > maxInt-n {
			panic("strings: Join output length overflow")
		}
		n += len(str)
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString(elems[0].String())
	for _, s := range elems[1:] {
		b.WriteString(sep)
		b.WriteString(s.String())
	}
	return b.String()
}
