// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT
package gotp

import (
	"crypto"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
)

var (
	hashEncoder = map[crypto.Hash]string{
		crypto.MD5:    "MD5",
		crypto.SHA1:   "SHA1",
		crypto.SHA256: "SHA256",
		crypto.SHA512: "SHA512",
	}
	hashDecoder = map[string]crypto.Hash{
		"MD5":    crypto.MD5,
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		"SHA512": crypto.SHA512,
	}
)

// OTP defines common functions for the one-time passwords
type OTP interface {
	// GenerateOTP generates new one-time password based on counter data
	GenerateOTP(counter int64) string
	// Verify confirms validity of provided otp code against given counter
	Verify(otp string, counter int64) bool
	// ProvisioningUri generates a provisioning URI for this OTP instance
	//
	// accountName identifies an account for which the URI is generated
	// issuer identifies the entity that performs authentication
	ProvisioningUri(accountName string, issuer string) string
}

// OTPKeyData contains data parsed from otpauth URL
type OTPKeyData struct {
	// OTP implementation, either *HOTP or *TOTP
	OTP OTP
	// Label contains user-visible label for the OTP
	Label string
	// Issuer contains the name of the issuer of the OTP
	Issuer string
}

func adjustForHash(key []byte, algorithm crypto.Hash) []byte {
	hash := algorithm.New()
	if len(key) > hash.BlockSize() { // if key is longer than block size
		keyHash := hash.Sum(key)
		key = keyHash[:]
	}
	if len(key) < hash.BlockSize() { // pad the key if needed
		key = append(key, make([]byte, hash.BlockSize()-len(key))...)
	}
	return key
}

// getLabelIssuer extracts label and issuer name from the URL
// label is populated from URL's account name
// if label contains issuer separated from the account name with ':', then issuer is extracted from the label
// if URL contains 'issuer' parameter then it overrides any other issuer value set previously
func getLabelIssuer(u *url.URL) (string, string) {
	label := u.Path[1:] // skip '/'
	var labelIssuer string
	if strings.Contains(label, ":") {
		lbl := strings.Split(label, ":")
		labelIssuer = lbl[0]
		label = lbl[1]
	}
	var issuer string
	if u.Query().Has(issuerKey) {
		issuer = u.Query().Get(issuerKey)
	} else {
		issuer = labelIssuer
	}
	return label, issuer
}

// EncodeKey converts a key to Base32 representation
//
// Padding symbols '=' are stripped from the end of string
func EncodeKey(key []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

// DecodeKey converts a Base32-encoded key to a byte slice
//
// key does not have to have proper '=' padding
func DecodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(key)
}

func algorithmFromName(algorithm string) (crypto.Hash, error) {
	algo, exists := hashDecoder[algorithm]
	if !exists {
		return 0, fmt.Errorf("algorithm '%s' is not supported", algorithm)
	} else {
		return algo, nil
	}
}

func HashAlgorithmName(algorithm crypto.Hash) (string, error) {
	algo, exists := hashEncoder[algorithm]
	if !exists {
		return "", fmt.Errorf("algorithm '%d' is not supported", algorithm)
	} else {
		return algo, nil
	}
}

const (
	typeHotp     = "hotp"
	typeTotp     = "totp"
	otpAuthSheme = "otpauth"
	secretKey    = "secret"
	issuerKey    = "issuer"
	digitsKey    = "digits"
	periodKey    = "period"
	counterKey   = "counter"
	algorithmKey = "algorithm"
	// DefaultDigits is the default length of the one-time passcode
	DefaultDigits = 6
	// SHA1 is the default hash algorithm used with HMAC
	SHA1 = "SHA1"
)

func generateProvisioningUri(otpType string, accountName string, issuer string, digits int, key []byte, extra url.Values) string {
	extra.Add(secretKey, EncodeKey(key))
	extra.Add(issuerKey, issuer)
	if digits != DefaultDigits {
		extra.Add(digitsKey, fmt.Sprintf("%d", digits))
	}
	u := url.URL{
		Scheme:   otpAuthSheme,
		Host:     otpType,
		Path:     url.PathEscape(issuer) + ":" + url.PathEscape(accountName),
		RawQuery: extra.Encode(),
	}
	return u.String()
}

// OTPFromUri returns a pointer to OTPKeyData structure that contains instance of one-time password implementation (eitehr HOTP or TOTP, depending on URL) and
// label and issuer information from the URI
func OTPFromUri(uri string) (*OTPKeyData, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme != otpAuthSheme {
		return nil, fmt.Errorf("unsupported URL scheme: %s, expected 'otpauth'", u.Scheme)
	}
	if u.Host == typeTotp {
		return NewTOTPFromUri(uri)
	} else if u.Host == typeHotp {
		return NewHOTPFromUri(uri)
	} else {
		return nil, fmt.Errorf("unsupported auth type: %s, expected 'totp' or 'hotp'", u.Host)
	}
}
