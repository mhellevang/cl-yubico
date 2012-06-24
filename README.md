cl-yubico
=========

Common Lisp yubico client for yubikey One Time Password validation (http://www.yubico.com/). The library implements YubiKey Validation Protocol version 2.0 as described in the specification (http://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20)

Depends on:
* drakma
* ironclad
* cl-base64
* url-rewrite

Usage:
* (cl-yubico:initialize id key) - to initialize client, where id your yubikey client id as an integer, and key is your API client key.
* (cl-yubico:verify otp) - to verify OTP, where otp param is a string containing a yubico one time password.