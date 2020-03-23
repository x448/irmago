package irmaclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AEADReader struct {
	r      io.Reader
	stream cipher.AEAD
}

type AEADWriter struct {
	w      io.Writer
	stream cipher.AEAD
}

func newAEADReader(r io.Reader, c cipher.AEAD) *AEADReader {
	return &AEADReader{r: r, stream: c}
}

func NewAEADWriter(w io.Writer, c cipher.AEAD) *AEADWriter {
	return &AEADWriter{w: w, stream: c}
}

func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (r *AEADReader) Read(out []byte) (int, error) {
	msg := make([]byte, 1024)
	n, err := r.r.Read(msg)
	if err != nil {
		return 0, err
	}
	nonce, ct := msg[:r.stream.NonceSize()], msg[r.stream.NonceSize():n]
	out, err = r.stream.Open(out[:0], nonce, ct, nil)
	if err != nil {
		return 0, err
	}
	mLen := n - r.stream.Overhead() - r.stream.NonceSize()
	return mLen, nil
}

func (w *AEADWriter) Write(in []byte) (int, error) {
	nonce := make([]byte, w.stream.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return 0, err
	}
	mLen := len(in) + w.stream.Overhead() + w.stream.NonceSize()
	msg := make([]byte, mLen)
	msg = w.stream.Seal(nonce, nonce, in, nil) // m = (nonce || enc(w.in, w.k))
	_, err = w.w.Write(msg)
	if err != nil {
		return 0, err
	}
	return mLen, nil
}

func Encrypt(c cipher.AEAD, in []byte) ([]byte, error) {
	nonce := make([]byte, c.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ctLen := len(in) + c.Overhead() + c.NonceSize()
	ct := make([]byte, ctLen)
	ct = c.Seal(nonce, nonce, in, nil) // m = (nonce || enc(in, key))
	return ct, nil
}

func Decrypt(c cipher.AEAD, ct []byte) ([]byte, error) {
	mLen := len(ct) - c.Overhead() - c.NonceSize()
	plain := make([]byte, mLen)
	nonce, ct := ct[:c.NonceSize()], ct[c.NonceSize():]
	plain, err := c.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
