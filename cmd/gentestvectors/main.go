// gentestvectors emits cryptographic test vectors using the Go standard library
// cryptographic routines to test the OpenSSL bindings.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"go/format"
	"io"
	"log"
	"math/rand"
	"os"
)

var outputPath = flag.String("out", "", "output path (default stdout)")

func init() {
	log.SetFlags(log.Llongfile)
	log.SetOutput(os.Stderr)
}

func main() {
	flag.Parse()

	var b bytes.Buffer
	fmt.Fprint(&b, "// Code generated by cmd/gentestvectors. DO NOT EDIT.\n\n")

	pkg := "openssl_test"
	if gopackage := os.Getenv("GOPACKAGE"); gopackage != "" {
		pkg = gopackage + "_test"
	}
	fmt.Fprintf(&b, "package %s\n\n", pkg)

	aesGCM(&b)

	generated, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatalf("failed to format generated code: %v", err)
	}

	if *outputPath != "" {
		err := os.WriteFile(*outputPath, generated, 0o644)
		if err != nil {
			log.Fatalf("failed to write output file: %v\n", err)
		}
	} else {
		_, _ = os.Stdout.Write(generated)
	}
}

func aesGCM(w io.Writer) {
	r := rand.New(rand.NewSource(0))

	fmt.Fprintln(w, `var aesGCMTests = []struct {
	description string
	key, nonce, plaintext, aad, ciphertext []byte
}{`)

	for _, keyLen := range []int{16, 24, 32} {
		for _, aadLen := range []int{0, 1, 3, 13, 30} {
			for _, plaintextLen := range []int{0, 1, 3, 13, 16, 51} {
				if aadLen == 0 && plaintextLen == 0 {
					continue
				}

				key := randbytes(r, keyLen)
				nonce := randbytes(r, 12)
				plaintext := randbytes(r, plaintextLen)
				aad := randbytes(r, aadLen)

				c, err := aes.NewCipher(key)
				if err != nil {
					panic(err)
				}
				aead, err := cipher.NewGCM(c)
				if err != nil {
					panic(err)
				}
				ciphertext := aead.Seal(nil, nonce, plaintext, aad)

				fmt.Fprint(w, "\t{\n")
				fmt.Fprintf(w, "\t\tdescription: \"AES-%d/AAD=%d/Plaintext=%d\",\n", keyLen*8, aadLen, plaintextLen)
				printBytesField(w, "key", key)
				printBytesField(w, "nonce", nonce)
				printBytesField(w, "plaintext", plaintext)
				printBytesField(w, "aad", aad)
				printBytesField(w, "ciphertext", ciphertext)
				fmt.Fprint(w, "\t},\n")
			}
		}
	}
	fmt.Fprintln(w, "}")
}

func randbytes(r *rand.Rand, n int) []byte {
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	r.Read(b)
	return b
}

func printBytesField(w io.Writer, name string, b []byte) {
	if len(b) == 0 {
		return
	}
	fmt.Fprintf(w, "\t\t%s: %#v,\n", name, b)
}
