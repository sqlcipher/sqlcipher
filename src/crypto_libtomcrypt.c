/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
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
#ifdef SQLCIPHER_CRYPTO_LIBTOMCRYPT
#include "sqliteInt.h"
#include "sqlcipher.h"
#include <tomcrypt.h>

typedef struct {
  prng_state prng;
} ltc_ctx;

static ltc_ctx *ltc_state = {0};
static unsigned int random_block_sz = 32;
static unsigned int ltc_init = 0;
static unsigned int ltc_ref_count = 0;
static sqlite3_mutex* ltc_rand_mutex = NULL;

static int sqlcipher_ltc_add_random(void *ctx, void *buffer, int length) {
  ltc_ctx *ltc = (ltc_ctx*)ctx;
  int rc, block_idx = 0;
  int block_count = length / random_block_sz;
  const unsigned char * data = (const unsigned char *)buffer;
#ifndef SQLCIPHER_LTC_NO_MUTEX_RAND
  sqlite3_mutex_enter(ltc_rand_mutex);
#endif
  for(; block_idx < block_count; block_idx++){
    rc = fortuna_add_entropy(data, random_block_sz, &(ltc->prng));
    data += random_block_sz;
    rc = rc != CRYPT_OK ? SQLITE_ERROR : SQLITE_OK;
    if(rc != SQLITE_OK) {
      break;
    }
  }
#ifndef SQLCIPHER_LTC_NO_MUTEX_RAND
  sqlite3_mutex_leave(ltc_rand_mutex);
#endif
  return rc;
}

static int sqlcipher_ltc_activate(void *ctx) {
  ltc_ctx *ltc = (ltc_ctx*)ctx;
  int random_buffer_sz = sizeof(char) * 32;
  unsigned char *random_buffer = sqlcipher_malloc(random_buffer_sz);
  sqlcipher_memset(random_buffer, 0, random_buffer_sz);
  
  if(ltc_init == 0) {
    if(register_prng(&fortuna_desc) != CRYPT_OK) return SQLITE_ERROR;
    if(register_cipher(&rijndael_desc) != CRYPT_OK) return SQLITE_ERROR;
    if(register_hash(&sha1_desc) != CRYPT_OK) return SQLITE_ERROR;
#ifndef SQLCIPHER_LTC_NO_MUTEX_RAND
    if(ltc_rand_mutex == NULL){
      ltc_rand_mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
    }
#endif
    if(fortuna_start(&(ltc->prng)) != CRYPT_OK) {
      return SQLITE_ERROR;
    }
    ltc_init = 1;
  }
  sqlite3_randomness(random_buffer_sz, random_buffer);
  if(sqlcipher_ltc_add_random(ctx, random_buffer, random_buffer_sz) != SQLITE_OK) {
    return SQLITE_ERROR;
  }
  if(sqlcipher_ltc_add_random(ctx, &ltc, sizeof(ltc_ctx*)) != SQLITE_OK) {
    return SQLITE_ERROR;
  }
  if(fortuna_ready(&(ltc->prng)) != CRYPT_OK) {
    return SQLITE_ERROR;
  }
  sqlcipher_free(random_buffer, random_buffer_sz);
  ltc_ref_count++;
  return SQLITE_OK;
}

static int sqlcipher_ltc_deactivate(void *ctx) {
  ltc_ctx *ltc = (ltc_ctx*)ctx;
  ltc_ref_count--;
  if(ltc_ref_count == 0){
    fortuna_done(&(ltc->prng));
#ifndef SQLCIPHER_LTC_NO_MUTEX_RAND
    sqlite3_mutex_free(ltc_rand_mutex);
    ltc_rand_mutex = NULL;
#endif
  }
  return SQLITE_OK;
}

static const char* sqlcipher_ltc_get_provider_name(void *ctx) {
  return "libtomcrypt";
}

static int sqlcipher_ltc_random(void *ctx, void *buffer, int length) {
  ltc_ctx *ltc = (ltc_ctx*)ctx;
  int rc;
  
  if((rc = fortuna_ready(&(ltc->prng))) != CRYPT_OK) {
    return SQLITE_ERROR;
  }
  fortuna_read(buffer, length, &(ltc->prng));
  return SQLITE_OK;
}

static int sqlcipher_ltc_hmac(void *ctx, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  int rc, hash_idx;
  hmac_state hmac;
  unsigned long outlen = key_sz;

  hash_idx = find_hash("sha1");
  if((rc = hmac_init(&hmac, hash_idx, hmac_key, key_sz)) != CRYPT_OK) return SQLITE_ERROR;
  if((rc = hmac_process(&hmac, in, in_sz)) != CRYPT_OK) return SQLITE_ERROR;
  if((rc = hmac_process(&hmac, in2, in2_sz)) != CRYPT_OK) return SQLITE_ERROR;
  if((rc = hmac_done(&hmac, out, &outlen)) != CRYPT_OK) return SQLITE_ERROR;
  return SQLITE_OK;
}

static int sqlcipher_ltc_kdf(void *ctx, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc, hash_idx;
  ltc_ctx *ltc = (ltc_ctx*)ctx;
  unsigned long outlen = key_sz;
  unsigned long random_buffer_sz = sizeof(char) * 256;
  unsigned char *random_buffer = sqlcipher_malloc(random_buffer_sz);
  sqlcipher_memset(random_buffer, 0, random_buffer_sz);

  hash_idx = find_hash("sha1");
  if((rc = pkcs_5_alg2(pass, pass_sz, salt, salt_sz,
                       workfactor, hash_idx, key, &outlen)) != CRYPT_OK) {
    return SQLITE_ERROR;
  }
  if((rc = pkcs_5_alg2(key, key_sz, salt, salt_sz,
                       1, hash_idx, random_buffer, &random_buffer_sz)) != CRYPT_OK) {
    return SQLITE_ERROR;
  }
  sqlcipher_ltc_add_random(ctx, random_buffer, random_buffer_sz);
  sqlcipher_free(random_buffer, random_buffer_sz);
  return SQLITE_OK;
}

static const char* sqlcipher_ltc_get_cipher(void *ctx) {
  return "rijndael";
}

static int sqlcipher_ltc_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int rc, cipher_idx;
  symmetric_CBC cbc;

  if((cipher_idx = find_cipher(sqlcipher_ltc_get_cipher(ctx))) == -1) return SQLITE_ERROR;
  if((rc = cbc_start(cipher_idx, iv, key, key_sz, 0, &cbc)) != CRYPT_OK) return SQLITE_ERROR;
  rc = mode == 1 ? cbc_encrypt(in, out, in_sz, &cbc) : cbc_decrypt(in, out, in_sz, &cbc);
  if(rc != CRYPT_OK) return SQLITE_ERROR;
  cbc_done(&cbc);
  return SQLITE_OK;
}

static int sqlcipher_ltc_set_cipher(void *ctx, const char *cipher_name) {
  return SQLITE_OK;
}

static int sqlcipher_ltc_get_key_sz(void *ctx) {
  int cipher_idx = find_cipher(sqlcipher_ltc_get_cipher(ctx));
  return cipher_descriptor[cipher_idx].max_key_length;
}

static int sqlcipher_ltc_get_iv_sz(void *ctx) {
  int cipher_idx = find_cipher(sqlcipher_ltc_get_cipher(ctx));
  return cipher_descriptor[cipher_idx].block_length;
}

static int sqlcipher_ltc_get_block_sz(void *ctx) {
  int cipher_idx = find_cipher(sqlcipher_ltc_get_cipher(ctx));
  return cipher_descriptor[cipher_idx].block_length;
}

static int sqlcipher_ltc_get_hmac_sz(void *ctx) {
  int hash_idx = find_hash("sha1");
  return hash_descriptor[hash_idx].hashsize;
}

static int sqlcipher_ltc_ctx_copy(void *target_ctx, void *source_ctx) {
  memcpy(target_ctx, source_ctx, sizeof(ltc_ctx));
  return SQLITE_OK;
}

static int sqlcipher_ltc_ctx_cmp(void *c1, void *c2) {
  return 1;
}

static int sqlcipher_ltc_ctx_init(void **ctx) {
  if(!ltc_state){
    ltc_state = sqlcipher_malloc(sizeof(ltc_ctx));
  }
  *ctx = ltc_state;
  if(*ctx == NULL) return SQLITE_NOMEM;
  sqlcipher_ltc_activate(*ctx);
  return SQLITE_OK;
}

static int sqlcipher_ltc_ctx_free(void **ctx) {
  sqlcipher_ltc_deactivate(&ctx);
  if(ltc_ref_count == 0){
    sqlcipher_free(*ctx, sizeof(ltc_ctx));
  }
  return SQLITE_OK;
}

int sqlcipher_ltc_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_ltc_activate;
  p->deactivate = sqlcipher_ltc_deactivate;
  p->get_provider_name = sqlcipher_ltc_get_provider_name;
  p->random = sqlcipher_ltc_random;
  p->hmac = sqlcipher_ltc_hmac;
  p->kdf = sqlcipher_ltc_kdf;
  p->cipher = sqlcipher_ltc_cipher;
  p->set_cipher = sqlcipher_ltc_set_cipher;
  p->get_cipher = sqlcipher_ltc_get_cipher;
  p->get_key_sz = sqlcipher_ltc_get_key_sz;
  p->get_iv_sz = sqlcipher_ltc_get_iv_sz;
  p->get_block_sz = sqlcipher_ltc_get_block_sz;
  p->get_hmac_sz = sqlcipher_ltc_get_hmac_sz;
  p->ctx_copy = sqlcipher_ltc_ctx_copy;
  p->ctx_cmp = sqlcipher_ltc_ctx_cmp;
  p->ctx_init = sqlcipher_ltc_ctx_init;
  p->ctx_free = sqlcipher_ltc_ctx_free;
  p->add_random = sqlcipher_ltc_add_random;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
