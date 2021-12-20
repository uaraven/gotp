package gotp

import (
	"crypto/subtle"
	"time"
)

// Totp is an implementation of RFC6238, Time-based one-time password algorithm
// Currently only HMAC-SHA1 is supported as underlying HMAC function
type Totp struct {
	Otp
	key      []byte
	t0       int64
	digits   int
	interval int
}

// DefaultInterval is the default time step and is equal to 30 seconds
const DefaultInterval = 30

// NewDefaultTotp creates an instance of Totp with the provided key and default parameters.
//
// Number of digits is 6, time step is 30 seconds and reference time is equal to Unix Epoch
//
// key is the shared secret key
func NewDefaultTotp(key []byte) *Totp {
	return NewTopt(key, 6, 30, 0)
}

// NewDefaultTotp creates an instance of Totp with the provided key and desired number of digits in the resulting code.
// Other TOTP parameters will use default values
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
func NewToptDigits(key []byte, digits int) *Totp {
	return NewTopt(key, digits, 30, 0)
}

// NewDefaultTotp creates an instance of Totp with the provided key and TOTP parameter values
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
//
// interval is the time step to use
//
// startTime is a Unix epoch timestamp to be used as a reference point
func NewTopt(key []byte, digits int, interval int, startTime int64) *Totp {
	key = adjustForSha1(key)
	return &Totp{
		key:      key,
		t0:       startTime,
		digits:   digits,
		interval: interval,
	}
}

// GenerateOTP generates a string containing numeric one-time password code
// based on the timestamp value
func (t *Totp) GenerateOTP(timestamp int64) string {
	timeSteps := (timestamp - t.t0) / int64(t.interval)
	h := NewHotpDigits(t.key, t.digits)
	return h.GenerateOTP(timeSteps)
}

// Now generates an one-time password based on current time
func (t *Totp) Now() string {
	return t.GenerateOTP(time.Now().Unix())
}

// Now generates an one-time password at the given time
//
// moment is a time for which to generate the one-time password
func (t *Totp) At(moment time.Time) string {
	return t.GenerateOTP(moment.Unix())
}

// Verify checks if the provided otp code is valid for the value of the given timestamp
//
// otp - otp code to verify
// timestamp - Unix epoch timestamp in seconds, agaist which the code will be verified
//
// Verify will either return false immediately if otp length is different from the number of digits this Totp
// is configured for or will perform constant-time comparision of the provided code and the expected code.
func (t *Totp) Verify(otp string, timestamp int64) bool {
	return t.VerifyWithinWindow(otp, timestamp, 0)
}

// VerifyNow checks if the provided otp code is valid for current time
//
// otp - otp code to verify
func (t *Totp) VerifyNow(otp string) bool {
	return t.VerifyWithinWindow(otp, time.Now().Unix(), 0)
}

// VerifyAt is similar to Verify, but accepts time.Time object instead of epoch timestamp
//
// otp - otp code to verify
// date - Date and time, agaist which the code will be verified
func (t *Totp) VerifyAt(otp string, date time.Time) bool {
	return t.VerifyWithinWindow(otp, date.Unix(), 0)
}

// VerifyWithinWindow checks if provided otp code is valid for the range of the ±validationWindow time-steps windows
// centered at timestamp
//
// This allows validation to pass if client's time is out of sync with server's time and to account for network delays
//
// It is recommended to keep validationWindow to a minimum to avoid exposing larger window for attack.
func (t *Totp) VerifyWithinWindow(otp string, timestamp int64, validationWindow int) bool {
	if len(otp) != t.digits {
		return false
	}
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

// VerifyAtWithinWindow is similar to VerifyWithinWindow, but accepts time.Time object instead of epoch timestamp
func (t *Totp) VerifyAtWithinWindow(otp string, date time.Time, validationWindow int) bool {
	return t.VerifyWithinWindow(otp, date.Unix(), validationWindow)
}
