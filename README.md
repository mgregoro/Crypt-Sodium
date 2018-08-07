## Note: GitHub Repository is a mirror of 

https://git.mg2.org/mikeyg/Crypt-Sodium

# Crypt-Sodium version 0.12

Simple wrapper around NaCL functions as provided by libsodium.  crypto_box, crypto_stream, crypto_hash,
and crypto_sign are all present and accounted for.  None of the specific implementations are exposed,
only the default implementations are, so please refer to your version of libsodium's release notes if 
you need to know what implementation you are using.

An attempt to adhere to the API provided by libsodium (inspired by NaCL) is made, but is broken wherever
an opportunity to be 'perlish' presented itself.  Don't expect to have to pass in or keep track of 
ciphertext or message lengths.  Should the convenience of the Perl API frustrate you, please note that
the *real* versions of the corresponding functions are available with the `real_` prefix.  e.g.
`real_crypto_stream_xor()`

A crude attempt to detect your version of libsodium using `pkg-config` and by inspecting canonical dirs
is made.  Falls back to the *minimum* level of support - `1.0.8`.  To troubleshoot feature detection run:

`perl Makefile.PL verbose`

### INSTALLATION

To install this module type the following:

    perl Makefile.PL
    make
    make test
    make install

### DEPENDENCIES

This module requires these other modules and libraries:

  [libsodium](https://download.libsodium.org/libsodium/releases/)

### COPYRIGHT AND LICENCE

Copyright (C) 2018 by Michael Gregorowicz

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.0 or,
at your option, any later version of Perl 5 you may have available.

