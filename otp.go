package gotp

// Otp defines common functions for the one-time passwords
type Otp interface {
	GenerateOTP(counter int64) string
	Validate(otp string, counter int64) bool
}
