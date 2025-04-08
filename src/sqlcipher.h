/* 
** SQLCipher
** sqlcipher.h developed by Stephen Lombardo (Zetetic LLC) 
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
#ifndef SQLCIPHER_H
#define SQLCIPHER_H

#include "sqlite3.h"

#define SQLCIPHER_HMAC_SHA1 0
#define SQLCIPHER_HMAC_SHA1_LABEL "HMAC_SHA1"
#define SQLCIPHER_HMAC_SHA256 1
#define SQLCIPHER_HMAC_SHA256_LABEL "HMAC_SHA256"
#define SQLCIPHER_HMAC_SHA512 2
#define SQLCIPHER_HMAC_SHA512_LABEL "HMAC_SHA512"


#define SQLCIPHER_PBKDF2_HMAC_SHA1 0
#define SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL "PBKDF2_HMAC_SHA1"
#define SQLCIPHER_PBKDF2_HMAC_SHA256 1
#define SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL "PBKDF2_HMAC_SHA256"
#define SQLCIPHER_PBKDF2_HMAC_SHA512 2
#define SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL "PBKDF2_HMAC_SHA512"

typedef struct sqlcipher_provider sqlcipher_provider;
struct sqlcipher_provider {
  int (*init)(void);
  void (*shutdown)(void);
  const char* (*get_provider_name)(void *ctx);
  int (*add_random)(void *ctx, const void *buffer, int length);
  int (*random)(void *ctx, void *buffer, int length);
  int (*hmac)(void *ctx, int algorithm,
              const unsigned char *hmac_key, int key_sz,
              const unsigned char *in, int in_sz,
              const unsigned char *in2, int in2_sz,
              unsigned char *out);
  int (*kdf)(void *ctx, int algorithm,
              const unsigned char *pass, int pass_sz,
              const unsigned char* salt, int salt_sz,
              int workfactor,
              int key_sz, unsigned char *key);
  int (*cipher)(void *ctx, int mode,
              const unsigned char *key, int key_sz,
              const unsigned char *iv,
              const unsigned char *in, int in_sz,
              unsigned char *out);
  const char* (*get_cipher)(void *ctx);
  int (*get_key_sz)(void *ctx);
  int (*get_iv_sz)(void *ctx);
  int (*get_block_sz)(void *ctx);
  int (*get_hmac_sz)(void *ctx, int algorithm);
  int (*ctx_init)(void **ctx);
  int (*ctx_free)(void **ctx);
  int (*fips_status)(void *ctx);
  const char* (*get_provider_version)(void *ctx);
  sqlcipher_provider *next;
};

/* public interfaces called externally */
int sqlcipher_extra_init(const char*);
void sqlcipher_extra_shutdown(void);
void sqlcipher_init_memmethods(void);
int sqlcipher_codec_pragma(sqlite3*, int, Parse*, const char *, const char*);
int sqlcipherCodecAttach(sqlite3*, int, const void *, int);
void sqlcipherCodecGetKey(sqlite3*, int, void**, int*);
int sqlcipher_find_db_index(sqlite3 *, const char *);

/* utility functions */
void* sqlcipher_memset(void *, unsigned char, sqlite_uint64);
int sqlcipher_ismemset(const void *, unsigned char, sqlite_uint64);
int sqlcipher_memcmp(const void *, const void *, int);
void* sqlcipher_malloc(sqlite_uint64);
void sqlcipher_free(void *, sqlite_uint64);
char* sqlcipher_version(void);

/* provider interfaces */
int sqlcipher_register_provider(sqlcipher_provider *);
sqlcipher_provider* sqlcipher_get_provider(void);

#define SQLCIPHER_MUTEX_PROVIDER          0
#define SQLCIPHER_MUTEX_PROVIDER_ACTIVATE 1
#define SQLCIPHER_MUTEX_PROVIDER_RAND     2
#define SQLCIPHER_MUTEX_RESERVED1         3
#define SQLCIPHER_MUTEX_RESERVED2         4
#define SQLCIPHER_MUTEX_RESERVED3         5
#define SQLCIPHER_MUTEX_MEM               6
#define SQLCIPHER_MUTEX_SHAREDCACHE       7
#define SQLCIPHER_MUTEX_COUNT             8

sqlite3_mutex* sqlcipher_mutex(int);

#define SQLCIPHER_LOG_NONE          0
#define SQLCIPHER_LOG_ANY           0xffffffff

#define SQLCIPHER_LOG_ERROR         (1<<0)
#define SQLCIPHER_LOG_WARN          (1<<1)
#define SQLCIPHER_LOG_INFO          (1<<2)
#define SQLCIPHER_LOG_DEBUG         (1<<3)
#define SQLCIPHER_LOG_TRACE         (1<<4)

#define SQLCIPHER_LOG_CORE          (1<<0)
#define SQLCIPHER_LOG_MEMORY        (1<<1)
#define SQLCIPHER_LOG_MUTEX         (1<<2)
#define SQLCIPHER_LOG_PROVIDER      (1<<3)

#ifdef SQLCIPHER_OMIT_LOG
#define sqlcipher_log(level, source, message, ...)
#else
void sqlcipher_log(unsigned int level, unsigned int source, const char *message, ...);
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

#endif
#endif
/* END SQLCIPHER */

