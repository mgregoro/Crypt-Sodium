#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "string.h"
#include "sodium.h"


MODULE = Crypt::Sodium		PACKAGE = Crypt::Sodium		

PROTOTYPES: ENABLE

SV *
crypto_stream_NONCEBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_stream_NONCEBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_stream_KEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_stream_KEYBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_box_NONCEBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_box_NONCEBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_box_PUBLICKEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_box_PUBLICKEYBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_box_SECRETKEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_box_SECRETKEYBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_box_SEEDBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_box_SEEDBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_sign_PUBLICKEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_sign_PUBLICKEYBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_secretbox_MACBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_secretbox_MACBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_box_MACBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_box_MACBYTES);

    OUTPUT:
        RETVAL


SV *
crypto_sign_SECRETKEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_sign_SECRETKEYBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_pwhash_SALTBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

    OUTPUT:
        RETVAL      

SV *
crypto_pwhash_OPSLIMIT()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);

    OUTPUT:
        RETVAL      

SV *
crypto_pwhash_OPSLIMIT_SENSITIVE()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);

    OUTPUT:
        RETVAL

SV *
crypto_pwhash_MEMLIMIT()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);

    OUTPUT:
        RETVAL    

SV *
crypto_pwhash_MEMLIMIT_SENSITIVE()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);

    OUTPUT:
        RETVAL    

SV *
crypto_pwhash_STRBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_pwhash_scryptsalsa208sha256_STRBYTES);

    OUTPUT:
        RETVAL    

SV *
randombytes_random()
    CODE:
        uint32_t r_bytes = randombytes_random();
        RETVAL = newSVuv((unsigned int) r_bytes);

    OUTPUT:
        RETVAL

SV *
randombytes_buf(size)
    unsigned long size

    CODE:
        unsigned char *buf[size];
        randombytes_buf(buf, size);
        RETVAL = newSVpv((const char * const)buf, size);
    OUTPUT:
        RETVAL

SV *
real_crypto_stream(clen, n, k)
    unsigned long clen
    unsigned char *n
    unsigned char *k

    CODE:
        unsigned char c[clen];
        crypto_stream(c, clen, n, k);
        RETVAL = newSVpv((unsigned char *)c, clen);

    OUTPUT:
        RETVAL

SV *
real_crypto_stream_xor(m, clen, n, k)
    unsigned char *m
    unsigned long clen
    unsigned char *n
    unsigned char *k

    CODE:
        unsigned char c[clen];
        crypto_stream_xor(c, m, clen, n, k);
        RETVAL = newSVpv((unsigned char *)c, clen);

    OUTPUT:
        RETVAL

SV *
real_crypto_box_open(c, clen, n, pk, sk)
    unsigned char *c 
    unsigned long clen
    unsigned char *n
    unsigned char *pk
    unsigned char *sk

    CODE:
        unsigned char *m = malloc(clen - crypto_box_MACBYTES);

        int status = crypto_box_open_easy((unsigned char*)m, (const unsigned char*)c, 
            (unsigned long long) clen, (const unsigned char*)n, (const unsigned char*)pk, (const unsigned char*)sk);

        if (status == 0) {
            RETVAL = newSVpv( m, clen - crypto_box_MACBYTES );
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_box(m, mlen, n, pk, sk)
    unsigned char *m 
    unsigned long mlen
    unsigned char *n
    unsigned char *pk
    unsigned char *sk

    CODE:
        unsigned char *c = malloc(mlen + crypto_box_MACBYTES);

        int status = crypto_box_easy((unsigned char*)c, (const unsigned char*)m, 
            (unsigned long long) mlen, (const unsigned char*)n, (const unsigned char*)pk, (const unsigned char*)sk);

        if (status == 0) {
            RETVAL = newSVpv( c, mlen + crypto_box_MACBYTES );
        } else {
            RETVAL = &PL_sv_undef;
        }   

    OUTPUT:
        RETVAL


SV *
real_crypto_secretbox_open(c, clen, n, sk)
    unsigned char *c 
    unsigned long clen
    unsigned char *n
    unsigned char *sk

    CODE:
        unsigned char *m = malloc(clen - crypto_secretbox_MACBYTES);

        int status = crypto_secretbox_open_easy((unsigned char *)m, (const unsigned char*)c, 
            (unsigned long long) clen, (const unsigned char*)n, (const unsigned char*)sk);

        if (status == 0) {
            RETVAL = newSVpv( m, clen - crypto_secretbox_MACBYTES );
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL


SV *
real_crypto_secretbox(m, mlen, n, sk)
    unsigned char *m 
    unsigned long mlen
    unsigned char *n
    unsigned char *sk

    CODE:
        unsigned char *c = malloc(mlen + crypto_secretbox_MACBYTES);

        int status = crypto_secretbox_easy((unsigned char*)c, (const unsigned char*)m, 
            (unsigned long long) mlen, (const unsigned char*)n, (const unsigned char*)sk);

        if (status == 0) {
            RETVAL = newSVpv( c, mlen + crypto_secretbox_MACBYTES );
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_hash(in, inlen)
    unsigned char * in
    unsigned long inlen

    CODE:
        unsigned char out[crypto_hash_BYTES];
        crypto_hash(out, in, (unsigned long long) inlen);

        // returning unsigned char * was truncating the data on NUL bytes, pack it 
        // in to an SV like this:
        RETVAL = newSVpv(out, crypto_hash_BYTES);
    
    OUTPUT:
        RETVAL

AV *
crypto_box_keypair()
    CODE:
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        unsigned char sk[crypto_box_SECRETKEYBYTES];

        crypto_box_keypair(pk, sk);

        SV* pk_sv = newSVpv(pk, crypto_box_PUBLICKEYBYTES);
        SV* sk_sv = newSVpv(sk, crypto_box_PUBLICKEYBYTES);

        RETVAL = newAV();

        av_push(RETVAL, pk_sv);
        av_push(RETVAL, sk_sv);

    OUTPUT:
        RETVAL

AV *
crypto_sign_keypair()
    CODE:
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];

        crypto_sign_keypair(pk, sk);

        SV* pk_sv = newSVpv(pk, crypto_sign_PUBLICKEYBYTES);
        SV* sk_sv = newSVpv(sk, crypto_sign_SECRETKEYBYTES);

        RETVAL = newAV();

        av_push(RETVAL, pk_sv);
        av_push(RETVAL, sk_sv);

    OUTPUT:
        RETVAL

SV *
real_crypto_sign(m, mlen, sk)
    unsigned char * m
    unsigned long mlen
    unsigned char * sk

    CODE:
        unsigned char * sm = malloc(mlen + crypto_sign_BYTES);
        unsigned long long smlen;
        int status = crypto_sign((unsigned char *)sm, &smlen, (const unsigned char *)m, 
            (unsigned long long)mlen, (const unsigned char *)sk);

        if (status == 0) {
            RETVAL = newSVpv((unsigned char *)sm, smlen);
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_sign_open(sm, smlen, pk)
    unsigned char * sm
    unsigned long smlen
    unsigned char * pk

    CODE:
        unsigned char * m = malloc(smlen);
        unsigned long long mlen;

        int status = crypto_sign_open((unsigned char *)m, &mlen, (const unsigned char *)sm, 
            (unsigned long long)smlen, (const unsigned char *)pk);

        if (status == 0) {
            RETVAL = newSVpv((unsigned char *)m, mlen);
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_pwhash_scrypt(klen, p, salt, opslimit, memlimit)
    unsigned long klen
    unsigned char *p
    unsigned char *salt
    unsigned long opslimit
    unsigned long memlimit

    CODE:
        unsigned char *k = malloc(klen);

        int status = crypto_pwhash_scryptsalsa208sha256((unsigned char*)k, klen,
            (unsigned char*)p, strlen(p), (const unsigned char*)salt, opslimit, memlimit);

        if (status == 0) {
            RETVAL = newSVpv((unsigned char *)k, klen);
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_pwhash_scrypt_str(p, salt, opslimit, memlimit)
    unsigned char *p
    unsigned char *salt
    unsigned long opslimit
    unsigned long memlimit

    CODE:
        unsigned char *hp = malloc(crypto_pwhash_scryptsalsa208sha256_STRBYTES);

        int status = crypto_pwhash_scryptsalsa208sha256_str((unsigned char*)hp, (unsigned char*)p, 
            strlen(p), opslimit, memlimit);

        if (status == 0) {
            RETVAL = newSVpv((unsigned char *)hp, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_pwhash_scrypt_str_verify(hp, p)
    unsigned char *hp
    unsigned char *p

    CODE:
        int status = crypto_pwhash_scryptsalsa208sha256_str_verify((unsigned char*)hp, (unsigned char*)p, 
            strlen(p));

        if (status == 0) {
            RETVAL = newSVuv((unsigned int) 1);
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL


