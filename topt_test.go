// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT
package gotp

import (
	"crypto"
	_ "crypto/sha256"
	"reflect"
	"testing"
	"time"
)

func TestTOTPGenerate(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewTOTPDigits(key, 8)

	expected := otp.GenerateOTP(59)
	if expected != "94287082" {
		t.Errorf("Expected '94287082', but got %s for time=59, digits=10, T0=0", expected)
	}

	expected = otp.GenerateOTP(1111111109)
	if expected != "07081804" {
		t.Errorf("Expected '07081804', but got %s for time=1111111109, digits=10, T0=0", expected)
	}

	expected = otp.GenerateOTP(20000000000)
	if expected != "65353130" {
		t.Errorf("Expected '65353130', but got %s for time=20000000000, digits=10, T0=0", expected)
	}
}

func TestHOTPGenerateOffset(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewTOTP(key, 8, 30, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	code := otp.At(time.Date(2000, 1, 1, 0, 0, 59, 0, time.UTC))

	if code != "94287082" {
		t.Errorf("Expected '94287082', but got %s for time=59, digits=10, T0=0", code)
	}
}

func TestTOTPVerifyDefault(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewTOTPDigits(key, 8)

	if !otp.Verify("94287082", 59) {
		t.Errorf("Failed validation of OTP '94287082' at 59 seconds")
	}

	if otp.Verify("94287082", 69) {
		t.Errorf("Incorrectly validated OTP '94287082' at 69 seconds")
	}
}

func TestTOTPVerifyWithWindow(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewTOTPDigits(key, 8)

	if !otp.VerifyWithinWindow("94287082", 69, 1) {
		t.Errorf("Failed validation of OTP '94287082' at 69 seconds with 1 interval window")
	}

	if !otp.VerifyWithinWindow("94287082", 31, 1) {
		t.Errorf("Failed validation of OTP '94287082' at 31 seconds with 1 interval window")
	}
}

func TestTotpUrlGenerator(t *testing.T) {
	totp := NewTOTPDigits([]byte("key"), 8)
	url := totp.ProvisioningUri("test@example.com", "Issuer")

	expected := "otpauth://totp/Issuer:test@example.com?digits=8&issuer=Issuer&secret=NNSXS"
	if url != expected {
		t.Errorf("Invalid url generated.\nExpected: %s\n  Actual: %s", expected, url)
	}

	totp = NewDefaultTOTP([]byte("key"))
	url = totp.ProvisioningUri("test@example.com", "Issuer")

	expected = "otpauth://totp/Issuer:test@example.com?issuer=Issuer&secret=NNSXS"
	if url != expected {
		t.Errorf("Invalid url generated.\nExpected: %s\n  Actual: %s", expected, url)
	}

	totp = NewTOTP([]byte("key"), 8, 45, 0)
	url = totp.ProvisioningUri("test@example.com", "Issuer")

	expected = "otpauth://totp/Issuer:test@example.com?digits=8&issuer=Issuer&period=45&secret=NNSXS"
	if url != expected {
		t.Errorf("Invalid url generated.\nExpected: %s\n  Actual: %s", expected, url)
	}

	totp = NewTOTPHash([]byte("key"), DefaultDigits, DefaultTimeStep, 0, crypto.SHA512)
	url = totp.ProvisioningUri("Example", "test@example.com")

	expected = "otpauth://totp/test@example.com:Example?algorithm=SHA512&issuer=test%40example.com&secret=NNSXS"
	if url != expected {
		t.Errorf("Invalid url generated.\nExpected: %s\n  Actual: %s", expected, url)
	}
}

func TestTotpUrlParser(t *testing.T) {
	data, err := NewTOTPFromUri("otpauth://totp/test1@example.com?digits=8&issuer=Issuer&secret=NNSXS")
	if err != nil {
		t.Error(err)
	}
	otp := data.OTP.(*TOTP)

	if data.Account != "test1@example.com" {
		t.Errorf("Error parsing label from URL")
	}
	if data.Issuer != "Issuer" {
		t.Errorf("Error parsing issuer from URL")
	}
	if !reflect.DeepEqual(otp.Secret, []byte("key")) {
		t.Errorf("Error parsing secret from URL")
	}
	if otp.Digits != 8 {
		t.Errorf("Error parsing digits from URL")
	}
	if otp.TimeStep != 30 {
		t.Errorf("Error setting default time step")
	}

	data, err = NewTOTPFromUri("otpauth://totp/Issuer:test@example.com?issuer=Overriden&period=45&secret=DDINI")
	if err != nil {
		t.Error(err)
	}
	otp = data.OTP.(*TOTP)
	if otp.Digits != 6 {
		t.Errorf("Error setting default digits")
	}
	if otp.TimeStep != 45 {
		t.Errorf("Error parsing time step from URL")
	}
	if data.Issuer != "Overriden" {
		t.Errorf("Error parsing issuer from URL")
	}

	data, err = NewTOTPFromUri("otpauth://totp/Issuer:test@example.com?algorithm=SHA256&secret=NNSXS")
	if err != nil {
		t.Error(err)
	}
	if data.Issuer != "Issuer" {
		t.Errorf("Error parsing issuer from URL")
	}
	otp = data.OTP.(*TOTP)
	if otp.Hash != crypto.SHA256 {
		t.Errorf("Error parsing time step from URL")
	}
}

func TestTotpUrlParserErrors(t *testing.T) {
	_, err := NewTOTPFromUri("otpauth://hotp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=DDINI")
	if err == nil {
		t.Errorf("Expected to fail because of invalid otp type")
	}
	_, err = NewTOTPFromUri("not_otpauth://totp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=DDINI")
	if err == nil {
		t.Errorf("Expected to fail because of invalid URI schema")
	}
	_, err = NewTOTPFromUri("otpauth://totp/test@example.com:Example?digits=8&issuer=test%40example.com")
	if err == nil {
		t.Errorf("Expected to fail because of missing secret")
	}
	_, err = NewTOTPFromUri("otpauth://totp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=X0NNSXS")
	if err == nil {
		t.Errorf("Expected to fail because of invalid secret")
	}
}
