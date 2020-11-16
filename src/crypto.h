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
/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#ifndef CRYPTO_H
#define CRYPTO_H

#include "sqliteInt.h"
#include "btreeInt.h"
#include "pager.h"

/* extensions defined in pager.c */ 
void *sqlite3PagerGetCodec(Pager*);
void sqlite3PagerSetCodec(Pager*, void *(*)(void*,void*,Pgno,int),  void (*)(void*,int,int),  void (*)(void*), void *);
int sqlite3pager_is_mj_pgno(Pager*, Pgno);
void sqlite3pager_error(Pager*, int);
void sqlite3pager_reset(Pager *pPager);

#if !defined (SQLCIPHER_CRYPTO_CC) \
   && !defined (SQLCIPHER_CRYPTO_LIBTOMCRYPT) \
   && !defined (SQLCIPHER_CRYPTO_NSS) \
   && !defined (SQLCIPHER_CRYPTO_OPENSSL)
#define SQLCIPHER_CRYPTO_OPENSSL
#endif

#define FILE_HEADER_SZ 16

#define CIPHER_XSTR(s) CIPHER_STR(s)
#define CIPHER_STR(s) #s

#ifndef CIPHER_VERSION_NUMBER
#define CIPHER_VERSION_NUMBER 4.4.2
#endif

#ifndef CIPHER_VERSION_BUILD
#define CIPHER_VERSION_BUILD community
#endif

#define CIPHER_DECRYPT 0
#define CIPHER_ENCRYPT 1

#define CIPHER_READ_CTX 0
#define CIPHER_WRITE_CTX 1
#define CIPHER_READWRITE_CTX 2

#ifndef PBKDF2_ITER
#define PBKDF2_ITER 256000
#endif

/* possible flags for cipher_ctx->flags */
#define CIPHER_FLAG_HMAC          0x01
#define CIPHER_FLAG_LE_PGNO       0x02
#define CIPHER_FLAG_BE_PGNO       0x04

#ifndef DEFAULT_CIPHER_FLAGS
#define DEFAULT_CIPHER_FLAGS CIPHER_FLAG_HMAC | CIPHER_FLAG_LE_PGNO
#endif


/* by default, sqlcipher will use a reduced number of iterations to generate
   the HMAC key / or transform a raw cipher key 
   */
#ifndef FAST_PBKDF2_ITER
#define FAST_PBKDF2_ITER 2
#endif

/* this if a fixed random array that will be xor'd with the database salt to ensure that the
   salt passed to the HMAC key derivation function is not the same as that used to derive
   the encryption key. This can be overridden at compile time but it will make the resulting
   binary incompatible with the default builds when using HMAC. A future version of SQLcipher
   will likely allow this to be defined at runtime via pragma */ 
#ifndef HMAC_SALT_MASK
#define HMAC_SALT_MASK 0x3a
#endif

#ifndef CIPHER_MAX_IV_SZ
#define CIPHER_MAX_IV_SZ 16
#endif

#ifndef CIPHER_MAX_KEY_SZ
#define CIPHER_MAX_KEY_SZ 64
#endif

#ifdef __ANDROID__
#include <android/log.h>
#endif

#ifdef CODEC_DEBUG
#ifdef __ANDROID__
#define CODEC_TRACE(...) {__android_log_print(ANDROID_LOG_DEBUG, "sqlcipher", __VA_ARGS__);}
#else
#define CODEC_TRACE(...)  {fprintf(stderr, __VA_ARGS__);fflush(stderr);}
#endif
#else
#define CODEC_TRACE(...)
#endif

#ifdef CODEC_DEBUG_MUTEX
#define CODEC_TRACE_MUTEX(...)  CODEC_TRACE(__VA_ARGS__)
#else
#define CODEC_TRACE_MUTEX(...)
#endif

#ifdef CODEC_DEBUG_MEMORY
#define CODEC_TRACE_MEMORY(...)  CODEC_TRACE(__VA_ARGS__)
#else
#define CODEC_TRACE_MEMORY(...)
#endif

#ifdef CODEC_DEBUG_PAGEDATA
#define CODEC_HEXDUMP(DESC,BUFFER,LEN)  \
  { \
    int __pctr; \
    printf(DESC); \
    for(__pctr=0; __pctr < LEN; __pctr++) { \
      if(__pctr % 16 == 0) printf("\n%05x: ",__pctr); \
      printf("%02x ",((unsigned char*) BUFFER)[__pctr]); \
    } \
    printf("\n"); \
    fflush(stdout); \
  }
#else
#define CODEC_HEXDUMP(DESC,BUFFER,LEN)
#endif

/* end extensions defined in pager.c */
 
/*
**  Simple shared routines for converting hex char strings to binary data
 */
static int cipher_hex2int(char c) {
  return (c>='0' && c<='9') ? (c)-'0' :
         (c>='A' && c<='F') ? (c)-'A'+10 :
         (c>='a' && c<='f') ? (c)-'a'+10 : 0;
}

static void cipher_hex2bin(const unsigned char *hex, int sz, unsigned char *out){
  int i;
  for(i = 0; i < sz; i += 2){
    out[i/2] = (cipher_hex2int(hex[i])<<4) | cipher_hex2int(hex[i+1]);
  }
}

static void cipher_bin2hex(const unsigned char* in, int sz, char *out) {
    int i;
    for(i=0; i < sz; i++) {
      sqlite3_snprintf(3, out + (i*2), "%02x ", in[i]);
    } 
}

static int cipher_isHex(const unsigned char *hex, int sz){
  int i;
  for(i = 0; i < sz; i++) {
    unsigned char c = hex[i];
    if ((c < '0' || c > '9') &&
        (c < 'A' || c > 'F') &&
        (c < 'a' || c > 'f')) {
      return 0;
    }
  }
  return 1;
}

/* extensions defined in crypto_impl.c */
/* the default implementation of SQLCipher uses a cipher_ctx
   to keep track of read / write state separately. The following
   struct and associated functions are defined here */
typedef struct {
  int derive_key;
  int pass_sz;
  unsigned char *key;
  unsigned char *hmac_key;
  unsigned char *pass;
  char *keyspec;
} cipher_ctx;


typedef struct {
  int store_pass;
  int kdf_iter;
  int fast_kdf_iter;
  int kdf_salt_sz;
  int key_sz;
  int iv_sz;
  int block_sz;
  int page_sz;
  int keyspec_sz;
  int reserve_sz;
  int hmac_sz;
  int plaintext_header_sz;
  int hmac_algorithm;
  int kdf_algorithm;
  unsigned int skip_read_hmac;
  unsigned int need_kdf_salt;
  unsigned int flags;
  unsigned char *kdf_salt;
  unsigned char *hmac_kdf_salt;
  unsigned char *buffer;
  Btree *pBt;
  cipher_ctx *read_ctx;
  cipher_ctx *write_ctx;
  sqlcipher_provider *provider;
  void *provider_ctx;
} codec_ctx ;

/* crypto.c functions */
int sqlcipher_codec_pragma(sqlite3*, int, Parse*, const char *, const char*);
int sqlite3CodecAttach(sqlite3*, int, const void *, int);
void sqlite3CodecGetKey(sqlite3*, int, void**, int*);
void sqlcipher_exportFunc(sqlite3_context *, int, sqlite3_value **);

/* crypto_impl.c functions */

void sqlcipher_init_memmethods(void);

/* activation and initialization */
void sqlcipher_activate(void);
void sqlcipher_deactivate(void);

int sqlcipher_codec_ctx_init(codec_ctx **, Db *, Pager *, const void *, int);
void sqlcipher_codec_ctx_free(codec_ctx **);
int sqlcipher_codec_key_derive(codec_ctx *);
int sqlcipher_codec_key_copy(codec_ctx *, int);

/* page cipher implementation */
int sqlcipher_page_cipher(codec_ctx *, int, Pgno, int, int, unsigned char *, unsigned char *);

/* context setters & getters */
void sqlcipher_codec_ctx_set_error(codec_ctx *, int);

void sqlcipher_codec_get_pass(codec_ctx *, void **, int *);
int sqlcipher_codec_ctx_set_pass(codec_ctx *, const void *, int, int);
void sqlcipher_codec_get_keyspec(codec_ctx *, void **zKey, int *nKey);

int sqlcipher_codec_ctx_set_pagesize(codec_ctx *, int);
int sqlcipher_codec_ctx_get_pagesize(codec_ctx *);
int sqlcipher_codec_ctx_get_reservesize(codec_ctx *);

void sqlcipher_set_default_pagesize(int page_size);
int sqlcipher_get_default_pagesize(void);

void sqlcipher_set_default_kdf_iter(int iter);
int sqlcipher_get_default_kdf_iter(void);
int sqlcipher_codec_ctx_set_kdf_iter(codec_ctx *, int);
int sqlcipher_codec_ctx_get_kdf_iter(codec_ctx *ctx);

int sqlcipher_codec_ctx_set_kdf_salt(codec_ctx *ctx, unsigned char *salt, int sz);
int sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx, void **salt);

int sqlcipher_codec_ctx_set_fast_kdf_iter(codec_ctx *, int);
int sqlcipher_codec_ctx_get_fast_kdf_iter(codec_ctx *);

const char* sqlcipher_codec_ctx_get_cipher(codec_ctx *ctx);

void* sqlcipher_codec_ctx_get_data(codec_ctx *);

void sqlcipher_set_default_use_hmac(int use);
int sqlcipher_get_default_use_hmac(void);

void sqlcipher_set_hmac_salt_mask(unsigned char mask);
unsigned char sqlcipher_get_hmac_salt_mask(void);

int sqlcipher_codec_ctx_set_use_hmac(codec_ctx *ctx, int use);
int sqlcipher_codec_ctx_get_use_hmac(codec_ctx *ctx);

int sqlcipher_codec_ctx_set_flag(codec_ctx *ctx, unsigned int flag);
int sqlcipher_codec_ctx_unset_flag(codec_ctx *ctx, unsigned int flag);
int sqlcipher_codec_ctx_get_flag(codec_ctx *ctx, unsigned int flag);

const char* sqlcipher_codec_get_cipher_provider(codec_ctx *ctx);
int sqlcipher_codec_ctx_migrate(codec_ctx *ctx);
int sqlcipher_codec_add_random(codec_ctx *ctx, const char *data, int random_sz);
int sqlcipher_cipher_profile(sqlite3 *db, const char *destination);
int sqlcipher_codec_get_store_pass(codec_ctx *ctx);
void sqlcipher_codec_get_pass(codec_ctx *ctx, void **zKey, int *nKey);
void sqlcipher_codec_set_store_pass(codec_ctx *ctx, int value);
int sqlcipher_codec_fips_status(codec_ctx *ctx);
const char* sqlcipher_codec_get_provider_version(codec_ctx *ctx);

int sqlcipher_set_default_plaintext_header_size(int size);
int sqlcipher_get_default_plaintext_header_size(void);
int sqlcipher_codec_ctx_set_plaintext_header_size(codec_ctx *ctx, int size);
int sqlcipher_codec_ctx_get_plaintext_header_size(codec_ctx *ctx);

int sqlcipher_set_default_hmac_algorithm(int algorithm);
int sqlcipher_get_default_hmac_algorithm(void);
int sqlcipher_codec_ctx_set_hmac_algorithm(codec_ctx *ctx, int algorithm);
int sqlcipher_codec_ctx_get_hmac_algorithm(codec_ctx *ctx);

int sqlcipher_set_default_kdf_algorithm(int algorithm);
int sqlcipher_get_default_kdf_algorithm(void);
int sqlcipher_codec_ctx_set_kdf_algorithm(codec_ctx *ctx, int algorithm);
int sqlcipher_codec_ctx_get_kdf_algorithm(codec_ctx *ctx);

void sqlcipher_set_mem_security(int);
int sqlcipher_get_mem_security(void);

int sqlcipher_find_db_index(sqlite3 *db, const char *zDb);

int sqlcipher_codec_ctx_integrity_check(codec_ctx *, Parse *, char *);

#endif
#endif
/* END SQLCIPHER */
