// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT

package gotp

import (
	"reflect"
	"testing"
)

func TestHOTPGenerate(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewHOTPDigits(key, 0, defaultDigits)
	expected := []string{
		"755224",
		"287082",
		"359152",
		"969429",
		"338314",
		"254676",
		"287922",
		"162583",
		"399871",
		"520489",
	}
	for i := range expected {
		actual := otp.CurrentOTP()
		if actual != expected[i] {
			t.Errorf("Counter: %d, Expected '%s', got '%s'", i, expected[i], actual)
		}
	}
}

func TestHOTPCounter(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewHOTPDigits(key, 100, defaultDigits)
	code1 := otp.CurrentOTP()
	if otp.GetCounter() != 101 {
		t.Errorf("Internal counter failed to increment")
	}
	code2 := otp.CurrentOTP()
	if otp.GetCounter() != 102 {
		t.Errorf("Internal counter failed to increment")
	}
	if code1 == code2 {
		t.Errorf("Subsequent calls to CurrentOTP() must produce different results")
	}
}

func TestHOTPVerify(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewHOTPDigits(key, 0, defaultDigits)

	expectedTrue := otp.Verify("338314", 4)

	if expectedTrue != true {
		t.Errorf("Failed to correctly validate code '338314' at couner 4")
	}

	expectedFalse := otp.Verify("542321", 12)

	if expectedFalse == true {
		t.Errorf("Falsely validated code '543321' at couner 12 as correct")
	}
}

func TestHotpUrlGenerator(t *testing.T) {
	hotp := NewHOTPDigits([]byte("key"), 342, 8)
	url := hotp.ProvisioningUri("Example", "test@example.com")

	expected := "otpauth://hotp/test@example.com:Example?counter=342&digits=8&issuer=test%40example.com&secret=DDINI"
	if url != expected {
		t.Errorf("Invalid url generated.\nExpected: %s\n  Actual: %s", expected, url)
	}

	hotp = NewDefaultHOTP([]byte("key"), 2342)
	url = hotp.ProvisioningUri("Example", "test@example.com")

	expected = "otpauth://hotp/test@example.com:Example?counter=2342&issuer=test%40example.com&secret=DDINI"
	if url != expected {
		t.Errorf("Invalid url generated.\nExpected: %s\n  Actual: %s", expected, url)
	}
}

func TestHotpUrlParser(t *testing.T) {
	data, err := NewHOTPFromUri("otpauth://hotp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=DDINI")
	if err != nil {
		t.Error(err)
	}
	otp := data.OTP.(*HOTP)

	if data.Label != "test@example.com:Example" {
		t.Errorf("Error parsing label from URL")
	}
	if data.Issuer != "test@example.com" {
		t.Errorf("Error parsing issuer from URL")
	}
	if !reflect.DeepEqual(otp.Secret, []byte("key")) {
		t.Errorf("Error parsing secret from URL")
	}
	if otp.Digits != 8 {
		t.Errorf("Error parsing digits from URL")
	}
	if otp.counter != 0 {
		t.Errorf("Error setting default counter")
	}

	data, err = NewHOTPFromUri("otpauth://hotp/test@example.com:Example?issuer=test%40example.com&counter=45&secret=DDINI")
	if err != nil {
		t.Error(err)
	}
	otp = data.OTP.(*HOTP)
	if otp.Digits != 6 {
		t.Errorf("Error setting default digits")
	}
	if otp.counter != 45 {
		t.Errorf("Error parsing counter from URL")
	}
}

func TestHotpUrlParserErrors(t *testing.T) {
	_, err := NewHOTPFromUri("otpauth://totp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=DDINI")
	if err == nil {
		t.Errorf("Expected to faile because of invalid otp type")
	}
	_, err = NewHOTPFromUri("not_otpauth://hotp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=DDINI")
	if err == nil {
		t.Errorf("Expected to faile because of invalid URI schema")
	}
	_, err = NewHOTPFromUri("otpauth://hotp/test@example.com:Example?digits=8&issuer=test%40example.com")
	if err == nil {
		t.Errorf("Expected to faile because of missing secret")
	}
	_, err = NewTOTPFromUri("otpauth://hotp/test@example.com:Example?digits=8&issuer=test%40example.com&secret=XDDINI")
	if err == nil {
		t.Errorf("Expected to faile because of invalid secret")
	}
}
