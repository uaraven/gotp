# GoTP: One-time password library for Go

GoTP library provides implementations of HMAC-based OTP ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)) and Time-based OTP ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)).

This library allows generation and validation of one-time passwords as used by variuos services. It is compatible with Google Authenticator and Authy.

Currently this library only supports HMAC-SHA1 as underlying HMAC algorithm 

# HMAC-based one-time password

```go

    import "github.com/uaraven/gotp"
    ...

    hotp := NewDefaultHotp([]byte("secret key"))
    counter := 10
    code := hotp.GenerateOTP(counter)

    if hotp.Verify(code, counter) {
        panic(fmt.Error("invalid OTP code"))
    }
```

`NewHotp` function creates HOTP instance with parameters such as number of digits in the one-time code and truncation offset. You can use `NewDefaultHotp` with the sane default parameters (6 digits, dynamic truncation).

`HOtp` also provides basic verification function. Resynchronization and verification throttling are out of scope for this library.

# TOTP

```go

    import (
        "github.com/uaraven/gotp"
        "time"
    )
    ...

    totp := NewDefaultTotp([]byte("secret key"))
    timestamp := time.Date(2021, 12, 20, 11, 28, 13, 0, time.UTC)
    code := totp.At(timestamp)

    if totp.VerifyAt(code, timestamp) {
        panic(fmt.Error("invalid OTP code"))
    }
```

TOTP parameters, such as number of digits in the resulting code, time step duration and starting time can be configured by using
`NewTotp` function. `NewDefaultTotp` creates a TOTP implementation with default parameters compatible with most authentication services.

`TOtp` instance provides functions to verify correctness of the one-time password at any time. It also supports verification within
the wider window to allow for out-of-sync clocks and network lag.

`VerifyWithinWindow(otp, timestamp, validationWindow)` will validate otp code within ±validateWindow time steps
around given timestamp. It is not recommended to use `validationWindow` values larger than 1 as this will expose larget window for attacks.

# License

This project is distributed under MIT license.
