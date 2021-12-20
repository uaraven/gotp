package gotp

import (
	"crypto/subtle"
	"time"
)

type Totp struct {
	Otp
	key      []byte
	t0       int64
	digits   int
	interval int
}

const DefaultInterval = 30

func NewDefaultTotp(key []byte) *Totp {
	return NewTopt(key, 6, 30, 0)
}

func NewToptDigits(key []byte, digits int) *Totp {
	return NewTopt(key, digits, 30, 0)
}

func NewTopt(key []byte, digits int, interval int, startTime int64) *Totp {
	key = adjustForSha1(key)
	return &Totp{
		key:      key,
		t0:       startTime,
		digits:   digits,
		interval: interval,
	}
}

func (t *Totp) GenerateOTP(timestamp int64) string {
	timeSteps := (timestamp - t.t0) / int64(t.interval)
	h := NewHotp(t.key, t.digits)
	return h.GenerateOTP(timeSteps)
}

func (t *Totp) Now() string {
	return t.GenerateOTP(time.Now().Unix())
}

func (t *Totp) At(moment time.Time) string {
	return t.GenerateOTP(moment.Unix())
}

func (t *Totp) Verify(otp string, timestamp int64) bool {
	return t.VerifyWithinWindow(otp, timestamp, 0)
}

func (t *Totp) VerifyWithinWindow(otp string, timestamp int64, validationWindow int) bool {
	value := []byte(otp)
	for i := -validationWindow; i <= validationWindow; i++ {
		ts := timestamp + int64(i)*int64(t.interval)
		expected := []byte(t.GenerateOTP(ts))
		if subtle.ConstantTimeCompare(value, expected) == 1 {
			return true
		}
	}
	return false
}
