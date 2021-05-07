//+build !local_tests

package myirmaserver

import (
	"bytes"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerLoginEmail(t *testing.T) {
	db := &myirmaMemoryDB{
		userData: map[string]memoryUserData{
			"testuser": {
				id:         15,
				lastActive: time.Unix(0, 0),
				email:      []string{"test@test.com"},
			},
			"noemail": {
				id:         17,
				lastActive: time.Unix(0, 0),
			},
		},
		loginEmailTokens: map[string]string{
			"testtoken": "test@test.com",
		},
		verifyEmailTokens: map[string]int64{
			"testemailtoken": 15,
		},
	}
	StartKeyshareServer(t, db, "localhost:1025")
	defer StopKeyshareServer(t)

	reqData := bytes.NewBufferString(`{"email": "dne", "language": "en"}`)
	res, err := http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.NotEqual(t, 204, res.StatusCode)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString(`{"email": "test@test.com", "language":"en"}`)
	res, err = http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString(`{"email": "test@test.com", "language":"dne"}`)
	res, err = http.Post("http://localhost:8080/login/email", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
	}

	reqData = bytes.NewBufferString(`{"username":"testuser", "token":"testtoken"}`)
	res, err = client.Post("http://localhost:8080/login/token", "application/json", reqData)
	require.NoError(t, err)
	require.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	reqData = bytes.NewBufferString("test@test.com")
	res, err = client.Post("http://localhost:8080/email/remove", "application/json", reqData)
	assert.NoError(t, err)
	assert.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()

	res, err = client.Post("http://localhost:8080/user/delete", "", nil)
	require.NoError(t, err)
	require.Equal(t, 204, res.StatusCode)
	_ = res.Body.Close()
}