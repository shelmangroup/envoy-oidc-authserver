package store

import (
	"time"
)

type Store interface {
	Get(token string) (b []byte, found bool, err error)
	Set(token string, b []byte, expiry time.Time) (err error)
	Delete(token string) (err error)
}
