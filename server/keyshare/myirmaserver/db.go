package myirmaserver

import (
	"net/http"
	"time"

	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
)

type MyirmaDB interface {
	UserID(username string) (int64, error)
	VerifyEmailToken(tx keyshare.Tx, token string) (int64, error)
	RemoveUser(id int64, delay time.Duration) error

	AddEmailLoginToken(tx keyshare.Tx, email, token string) error
	LoginTokenCandidates(token string) ([]LoginCandidate, error)
	TryUserLoginToken(tx keyshare.Tx, token, username string) (int64, error)

	UserInformation(id int64) (UserInformation, error)
	Logs(id int64, offset int, amount int) ([]LogEntry, error)
	AddEmail(id int64, email string) error
	RemoveEmail(id int64, email string, delay time.Duration) error

	SetSeen(tx keyshare.Tx, id int64) error

	Tx(
		w http.ResponseWriter, r *http.Request,
		f func(tx keyshare.Tx) (server.Error, string),
	)
}

type UserEmail struct {
	Email            string `json:"email"`
	DeleteInProgress bool   `json:"delete_in_progress"`
}

type UserInformation struct {
	Username         string      `json:"username"`
	Emails           []UserEmail `json:"emails"`
	language         string
	DeleteInProgress bool `json:"delete_in_progress"`
}

type LoginCandidate struct {
	Username   string `json:"username"`
	LastActive int64  `json:"last_active"`
}

type LogEntry struct {
	Timestamp int64   `json:"timestamp"`
	Event     string  `json:"event"`
	Param     *string `json:"param,omitempty"`
}
