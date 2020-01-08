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
#ifdef SQLCIPHER_CRYPTO_BEARSSL
#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "sqlcipher.h"
#include "bearssl_block.h"
#include "bearssl_hash.h"
#include "bearssl_hmac.h"
#include "bearssl_rand.h"

static const char * AES_256_CIPHER_NAME = "aes-256-cbc";
enum {
  AES_256_KEY_SIZE = 32,
  AES_256_CBC_BLOCK_SIZE = 16,
  HMAC_SHA1_SIZE = 20,
  HMAC_SHA256_SIZE = 32,
  HMAC_SHA512_SIZE = 64,
};

struct bearssl_ctx {
  br_hmac_drbg_context rng;
  const br_block_cbcenc_class *enc;
  const br_block_cbcdec_class *dec;
};

static int sqlcipher_bearssl_add_random(void *ctx, void *buffer, int length) {
  struct bearssl_ctx *bctx = ctx;
  if (!ctx || !buffer || length < 1 || length > SIZE_MAX) {
    return SQLITE_ERROR;
  }

  // Lock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_add_random: entering SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_add_random: entered SQLCIPHER_MUTEX_PROVIDER_RAND\n");

  // Update RNG
  br_hmac_drbg_update(&bctx->rng, buffer, (size_t) length);

  // Unlock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_add_random: leaving SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_add_random: left SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  return SQLITE_OK;
}

static int sqlcipher_bearssl_random(void *ctx, void *buffer, int length) {
  struct bearssl_ctx *bctx = ctx;
  if (!ctx || !buffer || length < 1 || length > SIZE_MAX) {
    return SQLITE_ERROR;
  }

  // Lock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_random: entering SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_random: entered SQLCIPHER_MUTEX_PROVIDER_RAND\n");

  // Generate random bytes
  br_hmac_drbg_generate(&bctx->rng, buffer, (size_t) length);

  // Unlock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_random: leaving SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_random: left SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  return SQLITE_OK;
}

static const char* sqlcipher_bearssl_get_provider_name(void *ctx) {
  return "bearssl";
}

static const char* sqlcipher_bearssl_get_provider_version(void *ctx) {
  return "unknown";
}

static int sqlcipher_bearssl_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  if (!ctx || !hmac_key || key_sz < 1 || key_sz > SIZE_MAX || !in || in_sz < 1 || in_sz > SIZE_MAX || (in2 && (in2_sz < 1 || in2_sz > SIZE_MAX)) || !out) {
    return SQLITE_ERROR;
  }

  // Initialise key based on algorithm
  br_hmac_key_context key_ctx;
  switch (algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      br_hmac_key_init(&key_ctx, &br_sha1_vtable, hmac_key, (size_t) key_sz);
      break;
    case SQLCIPHER_HMAC_SHA256:
      br_hmac_key_init(&key_ctx, &br_sha256_vtable, hmac_key, (size_t) key_sz);
      break;
    case SQLCIPHER_HMAC_SHA512:
      br_hmac_key_init(&key_ctx, &br_sha512_vtable, hmac_key, (size_t) key_sz);
      break;
    default:
      return SQLITE_ERROR;
  }

  // Calculate HMAC
  br_hmac_context hmac_ctx;
  br_hmac_init(&hmac_ctx, &key_ctx, 0);
  br_hmac_update(&hmac_ctx, in, (size_t) in_sz);
  if (in2) {
    br_hmac_update(&hmac_ctx, in2, (size_t) in2_sz);
  }
  br_hmac_out(&hmac_ctx, (void *) out);
  return SQLITE_OK; 
}

static int sqlcipher_bearssl_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int c, int key_sz, unsigned char *key) {
  if (!ctx || !pass || pass_sz < 1 || pass_sz > SIZE_MAX || !salt || salt_sz < 1 || salt_sz > SIZE_MAX || c < 1 || key_sz < 1 || key_sz > SIZE_MAX || !key) {
    return SQLITE_ERROR;
  }
  
  // Initialise key based on algorithm
  br_hmac_key_context key_ctx;
  switch (algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      br_hmac_key_init(&key_ctx, &br_sha1_vtable, pass, (size_t) pass_sz);
      break;
    case SQLCIPHER_HMAC_SHA256:
      br_hmac_key_init(&key_ctx, &br_sha256_vtable, pass, (size_t) pass_sz);
      break;
    case SQLCIPHER_HMAC_SHA512:
      br_hmac_key_init(&key_ctx, &br_sha512_vtable, pass, (size_t) pass_sz);
      break;
    default:
      return SQLITE_ERROR;
  }

  // PBKDF2 key derivation process
  size_t n_remaining = (size_t) key_sz;
  uint8_t *key_view = key;
  br_hmac_context hmac_ctx;
  br_hmac_init(&hmac_ctx, &key_ctx, 0);
  size_t hmac_size = br_hmac_size(&hmac_ctx);
  for (size_t i = 1; n_remaining > 0; ++i) {
    uint8_t block[hmac_size];
    uint8_t i_as_u32_be[4];
    uint8_t U[hmac_size];

    // U_1 = PRF(password, salt || u32_be(i))
    i_as_u32_be[0] = i >> 24;
    i_as_u32_be[1] = i >> 16;
    i_as_u32_be[2] = i >> 8;
    i_as_u32_be[3] = i;
    br_hmac_init(&hmac_ctx, &key_ctx, 0);
    br_hmac_update(&hmac_ctx, salt, (size_t) salt_sz);
    br_hmac_update(&hmac_ctx, i_as_u32_be, 4);
    br_hmac_out(&hmac_ctx, U);
    memcpy(block, U, hmac_size);

    // U_2 = PRF(password, U_1)
    // ...
    // U_c = PRF(password, U_c-1)
    for (int j = 1; j < c; ++j) {
      // U_j
      br_hmac_init(&hmac_ctx, &key_ctx, 0);
      br_hmac_update(&hmac_ctx, U, hmac_size);
      br_hmac_out(&hmac_ctx, U);

      // U_j-1 ^ U_j
      for (size_t k = 0; k < hmac_size; ++k) {
        block[k] ^= U[k];
      }
    }

    // Copy block (T_i) into resulting key buffer
    size_t n_copied = n_remaining < hmac_size ? n_remaining : hmac_size;
    memcpy(key_view, block, n_copied);
    n_remaining -= n_copied;
    key_view += n_copied;
  }
  return SQLITE_OK; 
}

static int sqlcipher_bearssl_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  const struct bearssl_ctx *bctx = ctx;
  if (!ctx || !key || key_sz != AES_256_KEY_SIZE || !iv || !in || in_sz > SIZE_MAX || in_sz % AES_256_CBC_BLOCK_SIZE != 0 || !out) {
    return SQLITE_ERROR;
  }

  uint8_t iv_copy[AES_256_CBC_BLOCK_SIZE];
  memcpy(out, in, (size_t) in_sz);
  memcpy(iv_copy, iv, AES_256_CBC_BLOCK_SIZE);
  switch (mode) {
    case CIPHER_DECRYPT: {
      // Decrypt
      br_aes_gen_cbcdec_keys keys;
      bctx->dec->init(&keys.vtable, key, (size_t) key_sz);
      bctx->dec->run(&keys.vtable, iv_copy, out, (size_t) in_sz);
      return SQLITE_OK;
    }

    case CIPHER_ENCRYPT: {
      // Encrypt
      br_aes_gen_cbcenc_keys keys;
      bctx->enc->init(&keys.vtable, key, (size_t) key_sz);
      bctx->enc->run(&keys.vtable, iv_copy, out, (size_t) in_sz);
      return SQLITE_OK; 
    }

    default:
      return SQLITE_ERROR;
  }
}

static const char* sqlcipher_bearssl_get_cipher(void *ctx) {
  return AES_256_CIPHER_NAME;
}

static int sqlcipher_bearssl_get_key_sz(void *ctx) {
  return AES_256_KEY_SIZE;
}

static int sqlcipher_bearssl_get_iv_sz(void *ctx) {
  return AES_256_CBC_BLOCK_SIZE;
}

static int sqlcipher_bearssl_get_block_sz(void *ctx) {
  return AES_256_CBC_BLOCK_SIZE;
}

static int sqlcipher_bearssl_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      return HMAC_SHA1_SIZE;
      break;
    case SQLCIPHER_HMAC_SHA256:
      return HMAC_SHA256_SIZE;
      break;
    case SQLCIPHER_HMAC_SHA512:
      return HMAC_SHA512_SIZE;
      break;
    default:
      return 0;
  }
}

static int sqlcipher_bearssl_ctx_init(void **ctx) {
  struct bearssl_ctx *bctx;
  br_prng_seeder seeder;
  const char* seeder_name = NULL;
  const char* aes_impl_name = NULL;
  int result = SQLITE_ERROR;

  // Lock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_init: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_init: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");

  // Allocate
  bctx = sqlcipher_malloc(sizeof(struct bearssl_ctx));

  // Initialise PRNG with a seed
  br_hmac_drbg_init(&bctx->rng, &br_sha256_vtable, NULL, 0);
  seeder = br_prng_seeder_system(&seeder_name);
  if (!seeder || !seeder(&bctx->rng.vtable) || !seeder_name) {
    goto out;
  }

  // Initialise AES 256 CBC cipher: x86ni > pwr8 > big
  // See: https://bearssl.org/speed.html
  bctx->enc = br_aes_x86ni_cbcenc_get_vtable();
  bctx->dec = br_aes_x86ni_cbcdec_get_vtable();
  aes_impl_name = "hw-x86ni";
  if (!bctx->enc || !bctx->dec) {
    bctx->enc = br_aes_pwr8_cbcenc_get_vtable();
    bctx->dec = br_aes_pwr8_cbcdec_get_vtable();
    aes_impl_name = "hw-pwr8";
    if (!bctx->enc || !bctx->dec) {
      bctx->enc = &br_aes_big_cbcenc_vtable;
      bctx->dec = &br_aes_big_cbcdec_vtable;
      aes_impl_name = "sw-big";
    }
  }

  // Debug output
  CODEC_TRACE("sqlcipher_bearssl_ctx_init: prng-seeder=%s aes-impl=%s\n", seeder_name, aes_impl_name);

  // Done
  result = SQLITE_OK;

out:
  if (result == SQLITE_OK) {
    *ctx = bctx;
  } else {
    sqlcipher_free(bctx, sizeof(struct bearssl_ctx));
  }

  // Unlock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_init: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_init: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  return result;
}

static int sqlcipher_bearssl_ctx_free(void **ctx) {
  // Lock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_free: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_free: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");

  // Free
  sqlcipher_free(*ctx, sizeof(struct bearssl_ctx));

  // Unlock
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_free: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_bearssl_ctx_free: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  return SQLITE_OK;
}

static int sqlcipher_bearssl_fips_status(void *ctx) {
  return 0;
}

int sqlcipher_bearssl_setup(sqlcipher_provider *p) {
  p->random = sqlcipher_bearssl_random;
  p->get_provider_name = sqlcipher_bearssl_get_provider_name;
  p->hmac = sqlcipher_bearssl_hmac;
  p->kdf = sqlcipher_bearssl_kdf;
  p->cipher = sqlcipher_bearssl_cipher;
  p->get_cipher = sqlcipher_bearssl_get_cipher;
  p->get_key_sz = sqlcipher_bearssl_get_key_sz;
  p->get_iv_sz = sqlcipher_bearssl_get_iv_sz;
  p->get_block_sz = sqlcipher_bearssl_get_block_sz;
  p->get_hmac_sz = sqlcipher_bearssl_get_hmac_sz;
  p->ctx_init = sqlcipher_bearssl_ctx_init;
  p->ctx_free = sqlcipher_bearssl_ctx_free;
  p->add_random = sqlcipher_bearssl_add_random;
  p->fips_status = sqlcipher_bearssl_fips_status;
  p->get_provider_version = sqlcipher_bearssl_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
