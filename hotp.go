// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT
package gotp

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"
	"crypto/subtle"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"sync"
)

// HOTP is an implementation of RFC4226, HMAC-based one-time password algorithm
type HOTP struct {
	OTP
	sync *sync.RWMutex
	// Hash is the Hash function used by HMAC
	Hash crypto.Hash
	// Secret is the original shared secret
	Secret []byte
	// Key is the secret padded to the required size
	Key []byte
	// Digits is a number of digits in the resulting code
	Digits int
	// counter is incremented every time HOTP is requested
	counter int64
	// TruncationOffset is offset value for truncation function
	TruncationOffset int
}

func hmac_hash(hashProvider func() hash.Hash, key, data []byte) []byte {
	hm := hmac.New(hashProvider, key)
	hm.Write(data)
	return hm.Sum([]byte{})
}

// NewHOTPFromUri creates an instance of HOTP with the parameters specified in URL
func NewHOTPFromUri(uri string) (*OTPKeyData, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme != otpAuthSheme {
		return nil, fmt.Errorf("unsupported URL scheme: %s, expected 'otpauth'", u.Scheme)
	}
	if u.Host != typeHotp {
		return nil, fmt.Errorf("unsupported auth type: %s, expected 'hotp'", u.Host)
	}
	if !u.Query().Has(secretKey) {
		return nil, fmt.Errorf("'secret' parameter required")
	}
	if !u.Query().Has(counterKey) {
		return nil, fmt.Errorf("'counter' parameter required")
	}
	label, issuer := getLabelIssuer(u)
	digits := int64(DefaultDigits)
	if u.Query().Has(digitsKey) {
		digits, err = strconv.ParseInt(u.Query().Get(digitsKey), 10, 32)
		if err != nil {
			return nil, err
		}
	}
	counter := int64(0)
	if u.Query().Has(counterKey) {
		counter, err = strconv.ParseInt(u.Query().Get(counterKey), 10, 32)
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
	key, err := DecodeKey(u.Query().Get(secretKey))
	if err != nil {
		return nil, err
	}

	return &OTPKeyData{
		OTP:    NewHOTPHash(key, counter, int(digits), -1, algorithm),
		Label:  label,
		Issuer: issuer}, nil
}

// NewDefaultHOTP crates an instance of Hotp with default parameters:
// Number of OTP digits is 6, SHA1 for hashing and using dynamic truncation offset
//
// key is the shared secret key
func NewDefaultHOTP(key []byte, counter int64) *HOTP {
	return NewHOTP(key, counter, DefaultDigits, -1)
}

// NewHOTPDigits creates an instance of Hotp with given number of digits for the OTP
// Maximum number of digits supported is 10.
//
// key is the shared secret key
// digits is the number of digits in the resulting one-time password code
func NewHOTPDigits(key []byte, counter int64, digits int) *HOTP {
	return NewHOTP(key, counter, digits, -1)
}

// NewHOTP allows to create an instance of Hotp and set the parameters
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
//
// algorithm is the hash function to use with HMAC, crypto.SHA1 is recommended
//
// truncationOffset is used by truncation function that is used to extract 4-byte dynamic binary
// code from HMAC result. The truncation offset value must be in range [0..HMAC result size in bytes).
// If truncationOffset value is outside of that range, then dynamic value will be used.
// By default value of truncationOffset is -1 and it is recommended to keep it this way
func NewHOTP(key []byte, counter int64, digits int, truncationOffset int) *HOTP {
	return NewHOTPHash(key, counter, digits, truncationOffset, crypto.SHA1)
}

// NewHOTPHash allows to create an instance of Hotp, set the parameters and chose hash function to be used in underlying HMAC
//
// key is the shared secret key
//
// digits is the number of digits in the resulting one-time password code
//
// algorithm is the hash function to use with HMAC, crypto.SHA1 is recommended
//
// truncationOffset is used by truncation function that is used to extract 4-byte dynamic binary
// code from HMAC result. The truncation offset value must be in range [0..HMAC result size in bytes).
// If truncationOffset value is outside of that range, then dynamic value will be used.
// By default value of truncationOffset is -1 and it is recommended to keep it this way
//
// hash is a hash function, one of crypto.* constants. You might need to add an import for selected hash function, otherwise you might see
// crypto: requested hash function is unavailable panic message.
// For example, if you want to use SHA512, then use crypto.SHA512 as a parameter and add 'import _ "crypto/sha512"' statement.
func NewHOTPHash(key []byte, counter int64, digits int, truncationOffset int, algorithm crypto.Hash) *HOTP {
	secret := key
	key = adjustForHash(key, algorithm)
	if digits > len(powers) {
		panic(fmt.Errorf("maximum supported number of digits is 10"))
	}
	return &HOTP{
		sync:             &sync.RWMutex{},
		Hash:             algorithm,
		Secret:           secret,
		Key:              key,
		Digits:           digits,
		counter:          counter,
		TruncationOffset: truncationOffset,
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

// CurrentOTP generates a string containing numeric one-time password code
// based on the internal counter value
//
// Counter is incremented automatically
func (h *HOTP) CurrentOTP() string {
	return h.GenerateOTP(h.counter)
}

// Current generates a string containing numeric one-time password code
// based on the internal counter value
//
// Counter is not changed
func (h *HOTP) generateNoIncrement(counter int64) string {
	defer h.sync.Unlock()
	h.sync.Lock()
	c := h.counter
	result := h.generateOTPCode(counter)
	h.counter = c
	return result
}

// SetCounter sets internal counter value
func (h *HOTP) SetCounter(newCounter int64) {
	defer h.sync.Unlock()
	h.sync.Lock()
	h.counter = newCounter
}

// GetCounter gets current internal counter value
func (h *HOTP) GetCounter() int64 {
	defer h.sync.RUnlock()
	h.sync.RLock()
	return h.counter
}

// GenerateOTP generates a string containing numeric one-time password code
// based on the counter value
//
// HOTP internal counter is set to the provided counter value before generating the new OTP code. Internal counter will be
// incremented after the code is generated
func (h *HOTP) GenerateOTP(counter int64) string {
	defer h.sync.Unlock()
	h.sync.Lock()
	return h.generateOTPCode(counter)
}

func (h *HOTP) VerifyCurrent(otp string) bool {
	if len(otp) != h.Digits {
		return false
	}
	expected := h.generateNoIncrement(h.counter)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(otp)) == 1
}

// Verify checks if provided otp code is valid for the value of counter
//
// otp - otp code to verify
// counter - counter value agaist which the code will be verified
//
// Verify will either return false immediately if otp length is different from the number of digits this Hotp
// is configured for or will perform constant-time comparision of the provided code and the expected code.
func (h *HOTP) Verify(otp string, counter int64) bool {
	if len(otp) != h.Digits {
		return false
	}
	expected := h.generateNoIncrement(counter)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(otp)) == 1
}

// Generates provisioning URI with the configured parameters as described in https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// Limitations:
//  - truncationOffset cannot be added to provisioning URI
//  - Only SHA1, SHA256 and SHA512 algorithms could be added to the URI, if HOTP is configured to use any other hashing function, no algorithm will be added to the URI
//    Note that many OTP generating applications (i.e. Google Authenticator) will ignore algorithm key and always use SHA1
//  - Current counter value will be added to URI, use SetCounter() to update it before generating URI
func (h *HOTP) ProvisioningUri(accountName string, issuer string) string {
	vals := make(url.Values)
	vals.Add(counterKey, fmt.Sprintf("%d", h.counter))
	algoName, err := HashAlgorithmName(h.Hash)
	if err == nil && h.Hash != crypto.SHA1 {
		vals.Add(algorithmKey, algoName)
	}
	return generateProvisioningUri(typeHotp, accountName, issuer, h.Digits, h.Secret, vals)
}

func (h *HOTP) generateOTPCode(counter int64) string {
	text := int64toBytes(counter)
	h.counter = counter + 1
	hash := hmac_hash(h.Hash.New, h.Key, text)
	var offset int = int(hash[len(hash)-1] & 0xf)
	if h.TruncationOffset >= 0 && h.TruncationOffset < len(hash)-4 {
		offset = h.TruncationOffset
	}
	binary := (int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		(int(hash[offset+3]) & 0xff)
	otp := binary % powers[h.Digits]
	return fmt.Sprintf("%0*d", h.Digits, otp)
}
