// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT
package gotp

import (
	"crypto"
	_ "crypto/sha1"
	"crypto/subtle"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// TOTP is an implementation of RFC6238, Time-based one-time password algorithm
type TOTP struct {
	OTP
	// hash is a hash function to be used for HMAC
	hash crypto.Hash
	// Secret is the original shared secret
	Secret []byte
	// Key is the secret padded to the required size
	Key []byte
	// StartTime, usually 0
	StartTime int64
	// Digits is a number of digits in the resulting code
	Digits int
	// TimeStep is an interval for which the one-time password is valid
	TimeStep int
}

// DefaultTimeStep is the default time step and is equal to 30 seconds
const DefaultTimeStep = 30

// NewTOTPFromUri creates an instance of TOTP with the parameters specified in URL
func NewTOTPFromUri(uri string) (*OTPKeyData, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme != otpAuthSheme {
		return nil, fmt.Errorf("unsupported URL scheme: %s, expected 'otpauth'", u.Scheme)
	}
	if u.Host != typeTotp {
		return nil, fmt.Errorf("unsupported auth type: %s, expected 'totp'", u.Host)
	}
	if !u.Query().Has(secretKey) {
		return nil, fmt.Errorf("'secret' parameter required")
	}
	label := u.Path[1:] // skip '/'
	issuer := u.Query().Get(issuerKey)
	digits := int64(DefaultDigits)
	if u.Query().Has(digitsKey) {
		digits, err = strconv.ParseInt(u.Query().Get(digitsKey), 10, 32)
		if err != nil {
			return nil, err
		}
	}
	interval := int64(DefaultTimeStep)
	if u.Query().Has(periodKey) {
		interval, err = strconv.ParseInt(u.Query().Get(periodKey), 10, 32)
		if err != nil {
			return nil, err
		}
	}
	algorithm := crypto.SHA1
	if u.Query().Has(algorithmKey) {
		algorithm, err = algorithmFromName(u.Query().Get(algorithmKey))
		if err != nil {
			return nil, err
		}
	}
	key, err := decodeKey(u.Query().Get(secretKey))
	if err != nil {
		return nil, err
	}

	return &OTPKeyData{
		OTP:    NewTOTPHash(key, int(digits), int(interval), 0, algorithm),
		Label:  label,
		Issuer: issuer}, nil
}

// NewDefaultTOTP creates an instance of Totp with the provided key and default parameters.
//
// Number of digits is 6, time step is 30 seconds and reference time is equal to Unix Epoch
//
// key is the shared secret key
func NewDefaultTOTP(key []byte) *TOTP {
	return NewTOTP(key, DefaultDigits, 30, 0)
}

// NewDefaultTotp creates an instance of Totp with the provided key and desired number of digits in the resulting code.
// Other TOTP parameters will use default values
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
func NewTOTPDigits(key []byte, digits int) *TOTP {
	return NewTOTP(key, digits, 30, 0)
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
func NewTOTP(key []byte, digits int, interval int, startTime int64) *TOTP {
	return NewTOTPHash(key, digits, interval, startTime, crypto.SHA1)
}

// NewDefaultTotp creates an instance of Totp with the provided key and TOTP parameter values. This function also allows to configure any hash function to be used in underlying HMAC
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
//
// interval is the time step to use
//
// startTime is a Unix epoch timestamp to be used as a reference point
//
// hash is a hash function, one of crypto.* constants. You might need to add an import for selected hash function, otherwise you might see
// crypto: requested hash function is unavailable panic message.
// For example, if you want to use SHA512, then use crypto.SHA512 as a parameter and add 'import _ "crypto/sha512"' statement.
func NewTOTPHash(key []byte, digits int, interval int, startTime int64, hash crypto.Hash) *TOTP {
	secret := key
	key = adjustForHash(key, hash)
	return &TOTP{
		Secret:    secret,
		Key:       key,
		StartTime: startTime,
		Digits:    digits,
		TimeStep:  interval,
		hash:      hash,
	}
}

// GenerateOTP generates a string containing numeric one-time password code
// based on the timestamp value
func (t *TOTP) GenerateOTP(timestamp int64) string {
	timeSteps := (timestamp - t.StartTime) / int64(t.TimeStep)
	h := NewHOTPDigits(t.Key, 0, t.Digits)
	return h.GenerateOTP(timeSteps)
}

// Now generates an one-time password based on current time
func (t *TOTP) Now() string {
	return t.GenerateOTP(time.Now().Unix())
}

// Now generates an one-time password at the given time
//
// moment is a time for which to generate the one-time password
func (t *TOTP) At(moment time.Time) string {
	return t.GenerateOTP(moment.Unix())
}

// Verify checks if the provided otp code is valid for the value of the given timestamp
//
// otp - otp code to verify
// timestamp - Unix epoch timestamp in seconds, agaist which the code will be verified
//
// Verify will either return false immediately if otp length is different from the number of digits this Totp
// is configured for or will perform constant-time comparision of the provided code and the expected code.
func (t *TOTP) Verify(otp string, timestamp int64) bool {
	return t.VerifyWithinWindow(otp, timestamp, 0)
}

// VerifyNow checks if the provided otp code is valid for current time
//
// otp - otp code to verify
func (t *TOTP) VerifyNow(otp string) bool {
	return t.VerifyWithinWindow(otp, time.Now().Unix(), 0)
}

// VerifyAt is similar to Verify, but accepts time.Time object instead of epoch timestamp
//
// otp - otp code to verify
// date - Date and time, agaist which the code will be verified
func (t *TOTP) VerifyAt(otp string, date time.Time) bool {
	return t.VerifyWithinWindow(otp, date.Unix(), 0)
}

// VerifyWithinWindow checks if provided otp code is valid for the range of the ±validationWindow time-steps windows
// centered at timestamp
//
// This allows validation to pass if client's time is out of sync with server's time and to account for network delays
//
// It is recommended to keep validationWindow to a minimum to avoid exposing larger window for attack.
func (t *TOTP) VerifyWithinWindow(otp string, timestamp int64, validationWindow int) bool {
	if len(otp) != t.Digits {
		return false
	}
	value := []byte(otp)
	for i := -validationWindow; i <= validationWindow; i++ {
		ts := timestamp + int64(i)*int64(t.TimeStep)
		expected := []byte(t.GenerateOTP(ts))
		if subtle.ConstantTimeCompare(value, expected) == 1 {
			return true
		}
	}
	return false
}

// VerifyAtWithinWindow is similar to VerifyWithinWindow, but accepts time.Time object instead of epoch timestamp
func (t *TOTP) VerifyAtWithinWindow(otp string, date time.Time, validationWindow int) bool {
	return t.VerifyWithinWindow(otp, date.Unix(), validationWindow)
}

// Generates provisioning URL with the configured parameters as described in https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// Limitations:
//  - startTime cannot be added to provisioning URL
//  - Only SHA1, SHA256 and SHA512 algorithms could be added to the URI, if TOTP is configured to use any other hashing function, no algorithm will be added to the URI
//    Note that many OTP generating applications (i.e. Google Authenticator) will ignore algorithm key and always use SHA1
func (t *TOTP) ProvisioningUri(accountName string, issuer string) string {
	vals := make(url.Values)
	if t.TimeStep != DefaultTimeStep {
		vals.Add(periodKey, fmt.Sprintf("%d", t.TimeStep))
	}
	algoName, err := algorithmToName(t.hash)
	if t.hash != crypto.SHA1 && err == nil {
		vals.Add(algorithmKey, algoName)
	}
	return generateProvisioningUri(typeTotp, accountName, issuer, t.Digits, t.Secret, vals)
}
