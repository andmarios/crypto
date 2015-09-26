package scrypt_benchmark

import (
	"testing"

	"golang.org/x/crypto/scrypt"
)

func benchmarkScrypt(b *testing.B, N, r, p int) {
	for n := 0; n < b.N; n++ {
		_, _ = scrypt.Key([]byte("qwertypass"), []byte("supersalt"), N, r, p, 32)
	}
}

func BenchmarkScrypt2_14__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<10, 8, 1)
}
func BenchmarkScrypt2_15__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<15, 8, 1)
}
func BenchmarkScrypt2_16__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<16, 8, 1)
}
func BenchmarkScrypt2_17__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<17, 8, 1)
}
func BenchmarkScrypt2_18__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<18, 8, 1)
}
func BenchmarkScrypt2_19__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<19, 8, 1)
}
func BenchmarkScrypt2_20__8__1(b *testing.B) {
	benchmarkScrypt(b, 2<<20, 8, 1)
}
func BenchmarkScrypt2_20__1__1(b *testing.B) {
	benchmarkScrypt(b, 2<<20, 1, 1)
}
