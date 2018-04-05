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
is(crypto_stream_xor(crypto_stream_xor('', $n, $k), $n, $k), '', "Testing roundtrip of ''");

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
is(crypto_box_open(crypto_box('', $n, $pk2, $sk1), $n, $pk1, $sk2), '', "Testing roundtrip of ''");
is(crypto_hash($message), crypto_hash($message), "Testing hash comparison");
is(length(randombytes_buf(24)), 24, "Testing randombytes_buf() output length");
ok(randombytes_random() > 0, "Testing randombytes_random() outputs a number greater than zero");
my $rbu = randombytes_uniform(255);
ok($rbu > 0 && $rbu < 255, "Testing randombytes_uniform() outputs an number within bounds");

# test password hashing functionality
my $cleartext = "abc123";
my $salt = crypto_pwhash_scrypt_salt();
my $key = crypto_pwhash_scrypt($cleartext, $salt);
is($key, crypto_pwhash_scrypt($cleartext, $salt), "sanity check crypto_hash_scrypt");

my $hp = crypto_pwhash_scrypt_str($cleartext, $salt);
is(crypto_pwhash_scrypt_str_verify($hp, $cleartext), 1, "test crypto_pwhash_scrypt_str_verify positive");
is(crypto_pwhash_scrypt_str_verify($hp, $cleartext . "not"), undef, "test crypto_pwhash_scrypt_str_verify negative");

my ($spk, $ssk) = sign_keypair();
# test sigs
my $signed = crypto_sign($cleartext, $ssk);
is(crypto_sign_open($signed, $spk), $cleartext, "verifying crypto_sign signed message");

# tests for crypto_generichash
my $hashed40 = crypto_generichash("Everybody Loves Chocolate", 40);
is(length($hashed40), 40, "crypto_generichash returns the right length hash");
is($hashed40, crypto_generichash("Everybody Loves Chocolate", 40), "crypto_generichash hashes match");
isnt($hashed40, crypto_generichash("Everybody Hates Chocolate", 40), "crypto_generichash hashes with different inputs don't match");

my $khashed32 = crypto_generichash_key("Everybody Hates Chocolate", 32, "ThisIsAFantasticHashKeyIsntIt");
is(length($khashed32), 32, "crypto_generichash_key returns the right length hash");
ok(
    $khashed32 eq crypto_generichash_key(
        "Everybody Hates Chocolate",
        32,
        "ThisIsAFantasticHashKeyIsntIt"
    ), "crypto_generichash_key hashes match"
);

ok(
    $khashed32 ne crypto_generichash_key(
        "Everybody Hates Chocolate",
        32,
        "ThisIsntAFantasticHashKeyIsIt"
    ), "crypto_generichash_key mismatch with a different key"
);

ok(
    $khashed32 ne crypto_generichash_key(
        "Everybody Loves Chocolate",
        32,
        "ThisIsAFantasticHashKeyIsntIt"
    ), "crypto_generichash_key mismatch with a different input"
);

# test detached sigs
my $sig = crypto_sign_detached($cleartext, $ssk);
is(crypto_sign_verify_detached($sig, $cleartext, $spk), 1, "verifying crypto_sign_detached signature");

# test scalarmult (key, shared secret derivation)
ok(crypto_scalarmult_base($sk1) eq $pk1, "derive public key from private key using crypto_scalarmult_base");
ok(crypto_scalarmult($sk1, $pk2) eq crypto_scalarmult($sk2, $pk1), "derive shared secret using crypto_scalarmult");
ok(crypto_scalarmult_safe($sk1, $pk2, $pk1) eq crypto_scalarmult_safe($sk2, $pk1, $pk2), 
    "derive shared secret using crypto_scalarmult_safe h(q || client_pub || server_pub)");

# crypto_generichash_init, update, and final... (hash append)
my $state = crypto_generichash_init("TheGreatestHashkeyEver");

is(ref($state), "Crypt::Sodium::GenericHash::State", "crypto_generichash_init() returns a ::GenericHash::State object");
is($state->{outlen}, 64, "default outlen of 64 automagically selected");

crypto_generichash_update($state, "Ever");
crypto_generichash_update($state, "ybody ");
crypto_generichash_update($state, "Loves Cocolate");

my $ikhashed64 = crypto_generichash_final($state);
is(length($ikhashed64), 64, "crypto_generichash_final output correct hash length");

my $state2 = crypto_generichash_init("TheGreatestHashkeyEver");
crypto_generichash_update($state2, "Everybody ");
crypto_generichash_update($state2, "Loves Cocolate");
my $ikhashed64_2 = crypto_generichash_final($state2);
is($ikhashed64, $ikhashed64_2, "multi-part hashes with the same inputs and keys are identical");

$state = crypto_generichash_init();
$state2 = crypto_generichash_init();

crypto_generichash_update($state, "Everybody Hates Chocolate");
crypto_generichash_update($state2, "Everybody Hates Chocolate");

$ikhashed64 = crypto_generichash_final($state);
$ikhashed64_2 = crypto_generichash_final($state2);

is($ikhashed64, $ikhashed64_2, "multi-part hashes with the same inputs and no keys are identical");

$state = crypto_generichash_init(undef, 32);
is($state->{outlen}, 32, "specifying alternate hash length works properly with undefined keys");

$state2 = crypto_generichash_init(undef, 32);

crypto_generichash_update($state, "Everybody Hates Chocolate");
crypto_generichash_update($state2, "Everybody Loves Chocolate");

$ikhashed64 = crypto_generichash_final($state);
$ikhashed64_2 = crypto_generichash_final($state2);

isnt($ikhashed64, $ikhashed64_2, "multi-part hashes with different inputs and no keys are different");

is($ikhashed64, crypto_generichash(
    "Everybody Hates Chocolate",
    32,
), "output of crypto_generichash_final with multiple update() calls same as crypto_generichash with same inputs");

my $pwh_salt = randombytes_buf(crypto_pwhash_SALTBYTES);
my @bytes = 
is(
    crypto_pwhash(64, "I am the eggman", $pwh_salt), 
    crypto_pwhash(64, "I am the eggman", $pwh_salt), 
    "crypto_pwhash, same input parameters, same key"
);

isnt(
    crypto_pwhash(64, "I am the eggman", $pwh_salt), 
    crypto_pwhash(64, "I am the walrus", randombytes_buf(crypto_pwhash_SALTBYTES)), 
    "crypto_pwhash, different input parameters, different key"
);

# let's use some resources...
my $ahashed = crypto_pwhash_str("Ultra Secret Fantastico", crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE);
ok(length($ahashed) == crypto_pwhash_STRBYTES, "returned a string crypto_pwhash_STRBYTES in length");
ok(crypto_pwhash_str_verify($ahashed, 'Ultra Secret Fantastico'), 'password verification succeeded, moderate-difficulty hash');
ok(!crypto_pwhash_str_verify($ahashed, 'Ultra Secretish Fantastico'), 'password verification failed on bad password, moderate difficulty');

# xchacha/poly1035
ok(my $xchacha_key = crypto_aead_xchacha20poly1305_ietf_keygen());
ok(length($xchacha_key) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "returned a string crypto_aead_xchacha20poly1305_ietf_KEYBYTES in length");
ok(my $xchacha_nonce = crypto_aead_xchacha20poly1305_ietf_nonce());
ok(length($xchacha_nonce) == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "returned a string crypto_aead_xchacha20poly1305_ietf_NPUBBYTES in length");
ok(my $ciphered = crypto_aead_xchacha20poly1305_ietf_encrypt("1234", "additional data", $xchacha_nonce, $xchacha_key), "xchacha/poly1035 encryption succeeded");
ok(crypto_aead_xchacha20poly1305_ietf_decrypt($ciphered, "additional data", $xchacha_nonce, $xchacha_key) eq "1234", "xchacha/poly1035 decryption succeeded");
ok(!crypto_aead_xchacha20poly1305_ietf_decrypt($ciphered, "wrong data", $xchacha_nonce, $xchacha_key), "xchacha/poly1035 decryption failed with bad AD");
ok(!crypto_aead_xchacha20poly1305_ietf_decrypt($ciphered, "additional data", "Wrong Nonce", $xchacha_key), "xchacha/poly1035 decryption failed with bad nonce");
ok(!crypto_aead_xchacha20poly1305_ietf_decrypt($ciphered, "additional data", $xchacha_nonce, "Wrong key"), "xchacha/poly1035 decryption failed with bad key");

done_testing();

