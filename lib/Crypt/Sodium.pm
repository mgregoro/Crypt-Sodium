package Crypt::Sodium;

use 5.018000;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT = qw(
    box_keypair
    sign_keypair
    crypto_sign
    real_crypto_sign
    crypto_sign_open
    real_crypto_sign_open
    crypto_box
    real_crypto_box
    crypto_box_open
    real_crypto_box_open
    crypto_hash
    real_crypto_hash
    crypto_stream
    real_crypto_stream
    crypto_stream_xor
    real_crypto_stream_xor
    crypto_box_keypair
    crypto_sign_keypair
    randombytes_buf
    randombytes_random
    crypto_stream_NONCEBYTES
    crypto_stream_KEYBYTES
    crypto_box_NONCEBYTES
    crypto_box_PUBLICKEYBYTES
    crypto_box_SECRETKEYBYTES
    crypto_sign_PUBLICKEYBYTES
    crypto_sign_SECRETKEYBYTES
    crypto_stream_key
    crypto_stream_nonce
    crypto_box_nonce
);

our $VERSION = '0.05';

use subs qw/
    crypto_stream_KEYBYTES
    crypto_stream_NONCEBYTES
    crypto_box_NONCEBYTES
    crypto_box_PUBLICKEYBYTES
    crypto_box_SECRETKEYBYTES
    crypto_sign_PUBLICKEYBYTES
    crypto_sign_SECRETKEYBYTES
/;

require XSLoader;
XSLoader::load('Crypt::Sodium', $VERSION);

sub crypto_box_nonce {
    return randombytes_buf(crypto_box_NONCEBYTES);
}

sub crypto_stream_key {
    return randombytes_buf(crypto_stream_KEYBYTES);
}

sub crypto_stream_nonce {
    return randombytes_buf(crypto_stream_NONCEBYTES);
}

sub crypto_stream {
    my ($len, $n, $k) = @_;

    unless (length($n) == crypto_stream_NONCEBYTES) {
        die "[fatal]: nonce must be exactly " . crypto_stream_NONCEBYTES . " bytes long.\n";
    }

    unless (length($k) == crypto_stream_KEYBYTES) {
        die "[fatal]: key must be exactly " . crypto_stream_KEYBYTES . " bytes long.\n";
    }

    return real_crypto_stream($len, $n, $k);
}

sub crypto_stream_xor {
    my ($m, $n, $k) = @_;

    unless (length($n) == crypto_stream_NONCEBYTES) {
        die "[fatal]: nonce must be exactly " . crypto_stream_NONCEBYTES . " bytes long.\n";
    }

    unless (length($k) == crypto_stream_KEYBYTES) {
        die "[fatal]: key must be exactly " . crypto_stream_KEYBYTES . " bytes long.\n";
    }

    return real_crypto_stream_xor($m, length($m), $n, $k);
}

sub crypto_hash {
    my ($to_hash) = @_;
    return real_crypto_hash($to_hash, length($to_hash));
}

sub box_keypair {
    my $ar = crypto_box_keypair();
    return (@$ar);
}

sub sign_keypair {
    my $ar = crypto_sign_keypair();
    return (@$ar);
}

sub crypto_sign_open {
    my ($sm, $pk) = @_;

    unless (length($pk) == crypto_sign_PUBLICKEYBYTES) {
        die "[fatal]: public key must be exactly " . crypto_sign_PUBLICKEYBYTES . " bytes long.\n";
    }

    return real_crypto_sign_open($sm, length($sm), $pk);
}

sub crypto_sign {
    my ($m, $sk) = @_;

    unless (length($sk) == crypto_sign_SECRETKEYBYTES) {
        die "[fatal]: secret key must be exactly " . crypto_sign_SECRETKEYBYTES . " bytes long.\n";
    }

    return real_crypto_sign($m, length($m), $sk);
}

sub crypto_box_open {
    my ($c, $n, $pk, $sk) = @_;

    unless (length($pk) == crypto_box_PUBLICKEYBYTES) {
        die "[fatal]: public key must be exactly " . crypto_box_PUBLICKEYBYTES . " bytes long.\n";
    }

    unless (length($sk) == crypto_box_SECRETKEYBYTES) {
        die "[fatal]: secret key must be exactly " . crypto_box_SECRETKEYBYTES . " bytes long.\n";
    }

    return real_crypto_box_open($c, length($c), $n, $pk, $sk);
}

sub crypto_box {
    my ($m, $n, $pk, $sk) = @_;

    unless (length($pk) == crypto_box_PUBLICKEYBYTES) {
        die "[fatal]: public key must be exactly " . crypto_box_PUBLICKEYBYTES . " bytes long.\n";
    }

    unless (length($sk) == crypto_box_SECRETKEYBYTES) {
        die "[fatal]: secret key must be exactly " . crypto_box_SECRETKEYBYTES . " bytes long.\n";
    }

    return real_crypto_box($m, length($m), $n, $pk, $sk);
}

# Preloaded methods go here.

1;
__END__

=head1 NAME

Crypt::Sodium - Perl bindings for libsodium (NaCL) https://github.com/jedisct1/libsodium

=head1 SYNOPSIS

  use Crypt::Sodium;

  my $k = crypto_stream_key();
  my $n = crypto_stream_nonce();

  my $ciphertext = crypto_stream_xor("Hello World!", $n, $k);
  my $cleartext = crypto_stream_xor($ciphertext, $n, $k);

=head1 DESCRIPTION

  Simple wrapper around NaCL functions as provided by libsodium.  crypto_box, crypto_stream, crypto_hash,
  and crypto_sign are all present and accounted for.  None of the specific implementations are exposed, 
  only the default implementations are.

  I'm releasing this, though I don't feel I have any business writing a Crypt:: namespace'd module.  SO, 
  if you use it, please use it with caution, and supply me with patches when you notice any security holes.  I
  will do my best to apply them and release new versions promptly.

=head2 EXPORT
 
 box_keypair()
   Usage: my ($public_key, $secret_key) = box_keypair();

 sign_keypair()
   Usage: my ($public_key, $secret_key) = sign_keypair();

 crypto_sign($message, $secret_key)
   Usage: my $signed_message = crypto_sign($m, $sk);

 crypto_sign_open($signed_message, $public_key)
   Usage: my $message = crypto_sign_open($sm, $pk);

 crypto_box($message, $nonce, $public_key, $secret_key)
   Usage: my $ciphertext = crypto_box($m, $n, $pk, $sk);
   Note: $nonce must be at least crypto_box_NONCEBYTES long.

 crypto_box_open($ciphertext, $nonce, $public_key, $secret_key)
   Usage: my $cleartext = crypto_box_open($c, $n, $pk, $sk);

 crypto_hash($to_hash)
   Usage: my $hash = crypto_hash($to_hash);

 crypto_stream($length, $nonce, $key)
   Usage: my $stream = crypto_stream($length, $nonce, $key);
   Note: $nonce must be at least crypto_stream_NONCEBYTES long, and $key must be at least crypto_stream_KEYBYTES long.

 crypto_stream_xor($message, $nonce, $key)
   Usage: my $ciphertext = crypto_stream_xor($message, $nonce, $key);
          my $cleartext = crypto_stream_xor($ciphertext, $nonce, $key);

   Note: $nonce must be at least crypto_stream_NONCEBYTES long, and $key must be at least crypto_stream_KEYBYTES long.

 randombytes_buf($length)
   Usage: my $bytes = randombytes(24);

 crypto_box_nonce()
   Usage: my $nonce = crypto_box_nonce()

 crypto_stream_nonce()
   Usage: my $nonce = crypto_stream_nonce()

 crypto_stream_key()
   Usage: my $key = crypto_stream_key()

=head1 SEE ALSO

 https://github.com/jedisct1/libsodium
 http://nacl.cr.yp.to/

=head1 AUTHOR

Michael Gregorowicz, E<lt>mike@mg2.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 Michael Gregorowicz

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself, either Perl version 5.18 or, at your option, any later version of Perl 5 you may have available.

=cut
