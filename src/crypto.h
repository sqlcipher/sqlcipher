/* 
** SQLCipher
** crypto.h developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** Copyright (c) 2008, ZETETIC LLC
** All rights reserved.
** 
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
** 
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**  
*/
/* BEGIN CRYPTO */
#ifdef SQLITE_HAS_CODEC
#ifndef CRYPTO_H
#define CRYPTO_H

#define FILE_HEADER_SZ 16

#ifndef CIPHER
#define CIPHER "aes-256-cbc"
#endif

#define CIPHER_DECRYPT 0
#define CIPHER_ENCRYPT 1

#define CIPHER_READ_CTX 0
#define CIPHER_WRITE_CTX 1
#define CIPHER_READWRITE_CTX 2

#ifndef PBKDF2_ITER
#define PBKDF2_ITER 4000
#endif

#ifndef DEFAULT_USE_HMAC
#define DEFAULT_USE_HMAC 1
#endif

/* by default, sqlcipher will use an equal number of rounds to generate
   the HMAC key as it will to generate the encryption key */
#ifndef HMAC_PBKDF2_ITER
#define HMAC_PBKDF2_ITER PBKDF2_ITER
#endif

/* this if a fixed random array that will be xor'd with the database salt to ensure that the
   salt passed to the HMAC key derivation function is not the same as that used to derive
   the encryption key. This can be overridden at compile time but it will make the resulting
   binary incompatible with the default builds when using HMAC. A future version of SQLcipher
   will likely allow this to be defined at runtime via pragma */ 
#ifndef HMAC_FIXED_SALT
#define HMAC_FIXED_SALT {42,172,104,131,19,119,84,255,184,238,54,135,186,222,53,250}
#endif

#ifndef HMAC_FIXED_SALT_SZ
#define HMAC_FIXED_SALT_SZ 16
#endif

#ifdef CODEC_DEBUG
#define CODEC_TRACE(X)  {printf X;fflush(stdout);}
#else
#define CODEC_TRACE(X)
#endif


/* extensions defined in pragma.c */ 
   
void sqlite3pager_get_codec(Pager *pPager, void **ctx);
int sqlite3pager_is_mj_pgno(Pager *pPager, Pgno pgno);
sqlite3_file *sqlite3Pager_get_fd(Pager *pPager);
void sqlite3pager_sqlite3PagerSetCodec(
  Pager *pPager,
  void *(*xCodec)(void*,void*,Pgno,int),
  void (*xCodecSizeChng)(void*,int,int),
  void (*xCodecFree)(void*),
  void *pCodec
);
/* end extensions defined in pragma.c */
 
/*
**  Simple shared routines for converting hex char strings to binary data
 */
static int cipher_hex2int(char c) {
  return (c>='0' && c<='9') ? (c)-'0' :
         (c>='A' && c<='F') ? (c)-'A'+10 :
         (c>='a' && c<='f') ? (c)-'a'+10 : 0;
}

static void cipher_hex2bin(const char *hex, int sz, unsigned char *out){
  int i;
  for(i = 0; i < sz; i += 2){
    out[i/2] = (cipher_hex2int(hex[i])<<4) | cipher_hex2int(hex[i+1]);
  }
}

/* extensions defined in crypto_impl.c */

typedef struct codec_ctx codec_ctx;

/* utility functions */
int sqlcipher_memcmp(const unsigned char *a0, const unsigned char *a1, int len);
int sqlcipher_pseudorandom(void *, int);
void sqlcipher_free(void *, int);

/* activation and initialization */
void sqlcipher_activate();
int sqlcipher_codec_ctx_init(codec_ctx **, Db *, Pager *, sqlite3_file *, const void *, int);
void sqlcipher_codec_ctx_free(codec_ctx **);
int sqlcipher_codec_key_derive(codec_ctx *);
int sqlcipher_codec_key_copy(codec_ctx *, int);

/* page cipher implementation */
int sqlcipher_page_cipher(codec_ctx *, int, Pgno, int, int, unsigned char *, unsigned char *);

/* context setters & getters */
void sqlcipher_codec_ctx_set_error(codec_ctx *, int);

int sqlcipher_codec_ctx_set_pass(codec_ctx *, const void *, int, int);
void sqlcipher_codec_get_pass(codec_ctx *, void **zKey, int *nKey);

int sqlcipher_codec_ctx_set_pagesize(codec_ctx *, int);
int sqlcipher_codec_ctx_get_pagesize(codec_ctx *);
int sqlcipher_codec_ctx_get_reservesize(codec_ctx *);

int sqlcipher_codec_ctx_set_kdf_iter(codec_ctx *, int, int);
void* sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx);

int sqlcipher_codec_ctx_set_hmac_kdf_iter(codec_ctx *, int, int);

int sqlcipher_codec_ctx_set_cipher(codec_ctx *, const char *, int);

void* sqlcipher_codec_ctx_get_data(codec_ctx *);

void sqlcipher_exportFunc(sqlite3_context *, int, sqlite3_value **);

int sqlcipher_codec_ctx_set_use_hmac(codec_ctx *ctx, int use);
/* end extensions defined in crypto_impl.c */

#endif
#endif
/* END CRYPTO */
