package irmaclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	testStorageDir = "../testdata/client"
)

var (
	cipherUsed = chacha20poly1305.NewX
)

func TestCryptoEncDec(t *testing.T) {
	key, _ := hex.DecodeString("77217A25432A462D4A614E645267556B58703273357638782F413F4428472B4B")
	plain1 := []byte("sometext")

	cipher, _ := cipherUsed(key)
	ct, err := Encrypt(cipher, plain1)
	require.NoError(t, err)
	plain2, err := Decrypt(cipher, ct)
	require.NoError(t, err)
	require.Equal(t, plain1, plain2, "decrypted ciphertext does not match plaintext")
}

func TestCryptoEncDecReadWriter(t *testing.T) {
	key, _ := hex.DecodeString("77217A25432A462D4A614E645267556B58703273357638782F413F4428472B4B")
	plain1 := []byte("sometext")
	plain2 := make([]byte, len(plain1))

	var buf bytes.Buffer
	var err error
	aead, _ := cipherUsed(key)

	encryptAES := NewAEADWriter(&buf, aead)
	encryptAES.Write(plain1)
	ct_bytes := buf.Bytes()

	byteReader := bytes.NewReader(ct_bytes)
	decryptAES := newAEADReader(byteReader, aead)

	n, err := decryptAES.Read(plain2)
	require.NoError(t, err)

	require.Equal(t, n, len(plain1), "decrypted length does not match plaintext length")
	require.Equal(t, plain1, plain2, "decrypted ciphertext does not match plaintext")
}

func TestCryptoEncDecReadWriterWrongKey(t *testing.T) {
	key, _ := hex.DecodeString("77217A25432A462D4A614E645267556B58703273357638782F413F4428472B4B")
	plain1 := []byte("sometext")
	plain2 := make([]byte, len(plain1))

	var buf bytes.Buffer
	var err error
	aead, _ := cipherUsed(key)

	encryptAES := NewAEADWriter(&buf, aead)
	encryptAES.Write(plain1)
	ct_bytes := buf.Bytes()

	key[12] = ^key[12]
	aead2, _ := cipherUsed(key)
	byteReader := bytes.NewReader(ct_bytes)
	decryptAES := newAEADReader(byteReader, aead2)

	_, err = decryptAES.Read(plain2)
	require.Error(t, err)
}

/* Checks if two files are identical by comparing
 * length and their respective checksums */
func eq(r1, r2 io.Reader) (bool, error) {
	w1, w2 := sha256.New(), sha256.New()
	n1, err := io.Copy(w1, r1)
	if err != nil {
		return false, err
	}
	n2, err := io.Copy(w2, r2)
	if err != nil {
		return false, err
	}
	var b1, b2 [sha256.Size]byte
	copy(b1[:], w1.Sum(nil))
	copy(b2[:], w2.Sum(nil))
	return n1 != n2 || b1 == b2, nil
}

/* TESTS to do full file encryption, fail because DB file too big */
func TestCryptoEncDecFile(t *testing.T) {
	key, _ := hex.DecodeString("77217A25432A462D4A614E645267556B58703273357638782F413F4428472B4B")
	fn := "test"
	dbfn := testStorageDir + "/" + fn
	dbctfn := testStorageDir + "/" + fn + "_ct"
	dborigfn := testStorageDir + "/" + fn + "_orig"
	aead, _ := cipherUsed(key)

	os.Remove(dbctfn)
	os.Remove(dborigfn)

	dbFile, err := os.OpenFile(dbfn, os.O_RDONLY, 0666)
	require.NoError(t, err)
	dbEncFile, err := os.OpenFile(dbctfn, os.O_WRONLY|os.O_CREATE, 0666)
	require.NoError(t, err)

	w := NewAEADWriter(dbEncFile, aead)
	_, err = io.Copy(w, dbFile)
	require.EqualError(t, err, "short write") // write > read because ct overhead
	dbEncFile.Close()

	dbEncFile, err = os.OpenFile(dbctfn, os.O_RDONLY, 0666)
	require.NoError(t, err)
	dbOrigFile, err := os.OpenFile(dborigfn, os.O_WRONLY|os.O_CREATE, 0666)
	require.NoError(t, err)

	r := newAEADReader(dbEncFile, aead)
	_, err = io.Copy(dbOrigFile, r)
	require.NoError(t, err)
	dbOrigFile.Close()

	dbOrigFile, err = os.OpenFile(dborigfn, os.O_RDONLY, 0666)
	require.NoError(t, err)

	ok, err := eq(dbFile, dbOrigFile)
	require.NoError(t, err)
	require.True(t, ok, "decryption of encrypted file does not match original")

	dbFile.Close()
	dbEncFile.Close()
	dbOrigFile.Close()
}

func TestCryptoEncDecFileWrongKey(t *testing.T) {
	key, _ := hex.DecodeString("77217A25432A462D4A614E645267556B58703273357638782F413F4428472B4B")
	fn := "test"
	dbfn := testStorageDir + "/" + fn
	dbctfn := testStorageDir + "/" + fn + "_ct"
	dborigfn := testStorageDir + "/" + fn + "_orig"
	aead, _ := cipherUsed(key)

	os.Remove(dbctfn)
	os.Remove(dborigfn)

	dbFile, err := os.OpenFile(dbfn, os.O_RDONLY, 0666)
	require.NoError(t, err)
	dbEncFile, err := os.OpenFile(dbctfn, os.O_WRONLY|os.O_CREATE, 0666)
	require.NoError(t, err)

	w := NewAEADWriter(dbEncFile, aead)
	_, err = io.Copy(w, dbFile)
	require.EqualError(t, err, "short write") // write > read because ct overhead
	dbEncFile.Close()

	dbEncFile, err = os.OpenFile(dbctfn, os.O_RDONLY, 0666)
	require.NoError(t, err)
	dbOrigFile, err := os.OpenFile(dborigfn, os.O_WRONLY|os.O_CREATE, 0666)
	require.NoError(t, err)

	key[12] = ^key[12]
	aead, _ = cipherUsed(key)
	r := newAEADReader(dbEncFile, aead)
	_, err = io.Copy(dbOrigFile, r)
	require.Error(t, err)

	dbFile.Close()
	dbOrigFile.Close()
}
