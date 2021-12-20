// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT

package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"net/url"
)

// Hotp is an implementation of RFC4226, HMAC-based one-time password algorithm
// Currently only HMAC-SHA1 is supported
type Hotp struct {
	OTP
	secret           []byte // unpadded secret key
	key              []byte
	digits           int
	truncationOffset int
}

func hmac_sha1(key, data []byte) []byte {
	hm := hmac.New(sha1.New, key)
	hm.Write(data)
	return hm.Sum([]byte{})
}

// NewDefaultHotp crates an instance of Hotp with default parameters:
// Number of OTP digits is 6 and using dynamic truncation offset
//
// key is the shared secret key
func NewDefaultHotp(key []byte) *Hotp {
	return NewHotp(key, defaultDigits, -1)
}

// NewHotpDigits creates an instance of Hotp with given number of digits for the OTP
// Maximum number of digits supported is 10.
//
// key is the shared secret key
// digits is the number of digits in the resulting one-time password code
func NewHotpDigits(key []byte, digits int) *Hotp {
	return NewHotp(key, digits, -1)
}

// NewHotp allows to create an instance of Hotp and set the parameters
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
//
// truncationOffset is used by truncation function that is used to extract 4-byte dynamic binary
// code from HMAC result. The truncation offset value must be in range [0..HMAC result size in bytes).
// If truncationOffset value is outside of that range, then dynamic value will be used.
// By default value of truncationOffset is -1 and it is recommended to keep it this way
func NewHotp(key []byte, digits int, truncationOffset int) *Hotp {
	secret := key
	key = adjustForSha1(key)
	if digits > len(powers) {
		panic(fmt.Errorf("maximum supported number of digits is 10"))
	}
	return &Hotp{
		secret:           secret,
		key:              key,
		digits:           digits,
		truncationOffset: truncationOffset,
	}
}

var powers = []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000}

func int64toBytes(d int64) []byte {
	result := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b := byte(d & 0xff)
		result[i] = b
		d >>= 8
	}
	return result
}

// GenerateOTP generates a string containing numeric one-time password code
// based on counter value
func (h *Hotp) GenerateOTP(counter int64) string {
	text := int64toBytes(counter)
	hash := hmac_sha1(h.key, text)
	var offset int = int(hash[len(hash)-1] & 0xf)
	if h.truncationOffset >= 0 && h.truncationOffset < sha1.Size-4 {
		offset = h.truncationOffset
	}
	binary := (int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		(int(hash[offset+3]) & 0xff)
	otp := binary % powers[h.digits]
	return fmt.Sprintf("%0*d", h.digits, otp)
}

// Verify checks if provided otp code is valid for the value of counter
//
// otp - otp code to verify
// counter - counter value agaist which the code will be verified
//
// Verify will either return false immediately if otp length is different from the number of digits this Hotp
// is configured for or will perform constant-time comparision of the provided code and the expected code.
func (h *Hotp) Verify(otp string, counter int64) bool {
	if len(otp) != h.digits {
		return false
	}
	expected := h.GenerateOTP(counter)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(otp)) == 1
}

// Generates provisioning URL with the configured parameters as described in https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// This function always use counter value of 0, which probably doesn't make much sense.
// It is recommended to use ProvisioningUrlWithCounter instead
//
// Note that truncationOffset cannot be added to provisioning URL
func (h *Hotp) ProvisioningUrl(accountName string, issuer string) string {
	return h.ProvisioningUrlWithCounter(accountName, issuer, 0)
}

// Generates provisioning URL with the configured parameters as described in https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// counter is the counter value to be included in the URL
//
// Note that truncationOffset cannot be added to provisioning URL
func (h *Hotp) ProvisioningUrlWithCounter(accountName string, issuer string, counter int64) string {
	vals := make(url.Values)
	vals.Add("counter", fmt.Sprintf("%d", counter))
	return generateProvisioningUrl("hotp", accountName, issuer, h.digits, h.secret, vals)
}
