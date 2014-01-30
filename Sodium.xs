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
crypto_sign_PUBLICKEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_sign_PUBLICKEYBYTES);

    OUTPUT:
        RETVAL

SV *
crypto_sign_SECRETKEYBYTES()
    CODE:
        RETVAL = newSVuv((unsigned int) crypto_sign_SECRETKEYBYTES);

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
        unsigned char * buf[size];
        randombytes_buf(buf, size);
        RETVAL = newSVpv((const char * const)buf, size);
    OUTPUT:
        RETVAL

SV *
real_crypto_stream(clen, n, k)
    unsigned long clen
    unsigned char * n
    unsigned char * k

    CODE:
        unsigned char c[clen];
        crypto_stream(c, clen, n, k);
        RETVAL = newSVpv((unsigned char *)c, clen);

    OUTPUT:
        RETVAL

SV *
real_crypto_stream_xor(m, clen, n, k)
    unsigned char * m
    unsigned long clen
    unsigned char * n
    unsigned char * k

    CODE:
        unsigned char c[clen];
        crypto_stream_xor(c, m, clen, n, k);
        RETVAL = newSVpv((unsigned char *)c, clen);

    OUTPUT:
        RETVAL

SV *
real_crypto_box_open(c, clen, n, pk, sk)
    unsigned char * c 
    unsigned long clen
    unsigned char * n
    unsigned char * pk
    unsigned char * sk

    CODE:
        int padding_required = 0;
        unsigned long original_clen = clen;

        int bytes_of_zeroes = crypto_box_BOXZEROBYTES;
        unsigned char * padding[bytes_of_zeroes];
        memset(padding, 0, bytes_of_zeroes);

        // check to see if we already have bytes_of_zeroes up front
        if (memcmp(c, padding, bytes_of_zeroes) != 0) {
            // some padding is required, let's determine how much.
            padding_required = 1;

            int bytes_in_a_row = bytes_of_zeroes;
            for (bytes_in_a_row = bytes_of_zeroes; bytes_in_a_row > 0; --bytes_in_a_row) {
                if (memcmp(c, padding, bytes_in_a_row) == 0) {
                    break;
                }
            }

            // this is how many zeroes we have to add.
            bytes_of_zeroes = (bytes_of_zeroes - bytes_in_a_row);
            clen += bytes_of_zeroes;
        } 

        unsigned char * m = malloc(clen);
        unsigned char * padded_c = malloc(clen);

        // do padding if we've determined we have to.
        if (padding_required == 1) {
            // set crypto_box_BOXZEROBYTES zeroes at the beginning
            memset(padded_c, 0, bytes_of_zeroes);

            // copy in our payload (including zeroes it may have come with)
            memcpy(padded_c + bytes_of_zeroes, c, original_clen);
        } else {
            // just copy the message, it's already good to go.
            memcpy(padded_c, c, clen);
        }

        int status = crypto_box_open((unsigned char *)m, (const unsigned char*)padded_c, 
            (unsigned long long) clen, (const unsigned char*)n, (const unsigned char*)pk, (const unsigned char*)sk);

        //printf("open_crypto_box Status is: %d\n", status);

        // get rid of the zero padding...
        unsigned char cleartext[(clen - crypto_box_ZEROBYTES) + 1];
        memcpy( cleartext, &m[crypto_box_ZEROBYTES], clen - crypto_box_ZEROBYTES );
        cleartext[(clen - crypto_box_ZEROBYTES)] = 0;

        if (status == 0) {
            RETVAL = newSVpv( cleartext, clen - crypto_box_ZEROBYTES );
        } else {
            RETVAL = &PL_sv_undef;
        }

    OUTPUT:
        RETVAL

SV *
real_crypto_box(m, mlen, n, pk, sk)
    unsigned char * m 
    unsigned long mlen
    unsigned char * n
    unsigned char * pk
    unsigned char * sk

    CODE:
        int padding_required = 0;
        unsigned long original_mlen = mlen;

        int bytes_of_zeroes = crypto_box_ZEROBYTES;
        unsigned char * padding[bytes_of_zeroes];
        memset(padding, 0, bytes_of_zeroes);

        // check to see if we already have bytes_of_zeroes up front
        if (memcmp(m, padding, crypto_box_ZEROBYTES) != 0) {
            // some padding is required, let's determine how much.
            padding_required = 1;

            int bytes_in_a_row = bytes_of_zeroes;
            for (bytes_in_a_row = bytes_of_zeroes; bytes_in_a_row > 0; --bytes_in_a_row) {
                if (memcmp(m, padding, bytes_in_a_row) == 0) {
                    break;
                }
            }

            // this is how many zeroes we have to add.
            bytes_of_zeroes = (bytes_of_zeroes - bytes_in_a_row);
            mlen += bytes_of_zeroes;
        }

        unsigned char * c = malloc(mlen);
        unsigned char * padded_m = malloc(mlen);

        // do padding if we've determined we have to.
        if (padding_required == 1) {
            // set crypto_box_ZEROBYTES zeroes at the beginning
            memset(padded_m, 0, bytes_of_zeroes);

            // copy in our payload (including zeroes it may have come with)
            memcpy(padded_m + bytes_of_zeroes, m, original_mlen);
        } else {
            // just copy the message, it's already good to go.
            memcpy(padded_m, m, mlen);
        }

        int status = crypto_box((unsigned char *)c, (const unsigned char*)padded_m, 
            (unsigned long long) mlen, (const unsigned char*)n, (const unsigned char*)pk, (const unsigned char*)sk);

        //printf("crypto_box Status is: %d\n", status);

        RETVAL = newSVpv((unsigned char *)c, mlen);

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
