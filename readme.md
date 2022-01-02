# GoTP: One-time password library for Go

GoTP library provides implementations of one-time password generators and validators.

This implemantation supports HMAC-based OTP ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)) and Time-based OTP ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)).

This library allows generation and validation of one-time passwords as used by variuos services. It is compatible with Google Authenticator and Authy.

It supports all hash functions in standard library crypto module and provides utility methods to create provisioning URIs from configured OTP generators and parse URIs to configured OTP generators.

# HMAC-based One-time Password

```go

    import "github.com/uaraven/gotp"
    ...

    counter := 10
    hotp := gotp.NewDefaultHOTP([]byte("secret key"), counter)
    code := hotp.CurrentOTP(counter)

    if hotp.Verify(code, counter) {
        panic(fmt.Error("invalid OTP code"))
    }

```

`NewHOTP` function creates HOTP instance with parameters such as number of digits in the one-time code and truncation offset. You can use `NewDefaultHOTP` with the sane default parameters (6 digits, dynamic truncation, SHA1 hash function).

Default counter value must be provided every time when instance of `HOTP` is created. The counter will increment every time new one-time
password is requested. Counter can be reset by either setting it directly with `HOTP.SetCounter(value)` or by calling `HOTP.GenerateOTP(counter)`. In the latter case internal HOTP counter will be updated to the new value and the counter will be incremented after the one-time password is generated.

`HOTP` also provides basic verification function. Resynchronization and verification throttling are out of scope for this library.

# Time-based One-time Password

```go

    import (
        "github.com/uaraven/gotp"
        "time"
    )
    ...

    totp := gotp.NewDefaultTOTP([]byte("secret key"))
    timestamp := time.Date(2021, 12, 20, 11, 28, 13, 0, time.UTC)
    code := totp.At(timestamp)

    if totp.VerifyAt(code, timestamp) {
        panic(fmt.Error("invalid OTP code"))
    }
```

TOTP parameters, such as number of digits in the resulting code, time step duration and starting time can be configured by using
`NewTOTP` function. `NewDefaultTOTP` creates a TOTP implementation with default parameters compatible with most authentication services.

`TOTP` instance provides functions to verify correctness of the one-time password at any time. It also supports verification within
the wider window to allow for out-of-sync clocks and network lag.

`VerifyWithinWindow(otp, timestamp, validationWindow)` will validate otp code within ±validateWindow time steps
around given timestamp. It is not recommended to use `validationWindow` values larger than 1 as this will expose larget window for attacks.

# Provisioning URLs

GoTP supports generating and parsing of [Google Authenticator-compatible URLs](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

To generate a new provisioning URL use `ProvisioningUri(label string, issuer string) string` function in `OTP` interface.

To create an OTP generator from URL use `OTPFromUri(uri string) (*OTPKeyData, error)` function. It will return pointer to `OTPKeyData` structure that contains instance of the generator and, additionally, label and issuer fields from the URI.

# Notes on hash functions

This library will work with all hash functions defined in `crypto` module. Default hash function used is `SHA-1`. 

If you see following error

```
panic: crypto: requested hash function #X is unavailable
```

you need to import corresponding module so that the hash function can register itself with crypto module.

For example if you want to use TOTP with SHA-512 hash

```go
    import (
        "github.com/uaraven/gotp"
        "crypto"
        _ "crypto/sha512" // you need this
    )
    ...

    totp := gotp.NewTOTPHash([]byte("secret key"), DefaultDigits, DefaultTimeStep, 0, crypto.SHA512)
    code := totp.Now()
```

When generating provisioning URI, `algorithm` parameter will be included only if the hash function is one of SHA1, SHA256 or SHA512. 
Note that some of popular one-time passcode generation applications (like Google Authenticator) will ignore `algorithm` parameter and always use SHA1.

# License

This project is distributed under MIT license, except portions that are licensed under ISC license (see [NOTICE.txt](migration/NOTICE.txt)) in /migration folder.
