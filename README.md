Crypt-Sodium version 0.04
=========================

Simple wrapper around NaCL functions as provided by libsodium.  crypto_box, crypto_stream, crypto_hash,
and crypto_sign are all present and accounted for.  None of the specific implementations are exposed,
only the default implementations are.

I'm releasing this, though I don't feel I have any business writing a Crypt:: namespace'd module.  SO,
if you use it, please use it with caution, and supply me with patches when you notice any security holes.  I
will do my best to apply them and release new versions promptly.

INSTALLATION

To install this module type the following:

   perl Makefile.PL
   make
   make test
   make install

DEPENDENCIES

This module requires these other modules and libraries:

  libsodium (download.libsodium.org/libsodium/releases/)

COPYRIGHT AND LICENCE

Copyright (C) 2014 by Michael Gregorowicz

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.18.0 or,
at your option, any later version of Perl 5 you may have available.

