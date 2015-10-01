# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Crypt-Sodium.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More;
BEGIN { use_ok('Crypt::Sodium') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $message = "Hello World";
my $k = crypto_stream_key();
my $n = crypto_stream_nonce();
my $enciphered = crypto_stream_xor($message, $n, $k);
is(crypto_stream_xor($enciphered, $n, $k), $message, "Testing roundtrip of crypto_stream_xor");

# test crypto secret box stuff
$k = crypto_stream_key();
$n = crypto_box_nonce();
$enciphered = crypto_secretbox($message, $n, $k);
is(crypto_secretbox_open($enciphered, $n, $k), $message, "Testing roundtrip of crypto_secretbox");

# public key crypto
my ($pk1, $sk1) = box_keypair();
my ($pk2, $sk2) = box_keypair();

$n = crypto_box_nonce();
$enciphered = crypto_box($message, $n, $pk2, $sk1);
is(crypto_box_open($enciphered, $n, $pk1, $sk2), $message, "Testing roundtrip of crypto_box");
is(crypto_hash($message), crypto_hash($message), "Testing hash comparison");
is(length(randombytes_buf(24)), 24, "Testing random bytes output");

# test new password hashing functionality
my $cleartext = "abc123";
my $salt = crypto_pwhash_salt;
my $key = crypto_pwhash_scrypt($cleartext, $salt);
is($key, crypto_pwhash_scrypt($cleartext, $salt), "sanity check crypto_hash_scrypt");

my $hp = crypto_pwhash_scrypt_str($cleartext, $salt);
is(crypto_pwhash_scrypt_str_verify($hp, $cleartext), 1, "test crypto_pwhash_scrypt_str_verify positive");
is(crypto_pwhash_scrypt_str_verify($hp, $cleartext . "not"), undef, "test crypto_pwhash_scrypt_str_verify negative");

done_testing();