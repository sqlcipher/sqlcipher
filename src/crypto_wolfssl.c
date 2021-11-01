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
#ifdef SQLCIPHER_CRYPTO_WOLFSSL
#include "crypto.h"
#include "sqlcipher.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/version.h>

int sqlcipher_wolf_setup(sqlcipher_provider *p);

#ifdef HAVE_FIPS
#include <wolfssl/wolfcrypt/fips_test.h>
static void wcFipsCb(int ok, int err, const char* hash)
{
    CODEC_TRACE("wolfCrypt Fips error callback, ok = %d, err = %d\n", ok, err);
    CODEC_TRACE("message = %s\n", wc_GetErrorString(err));
    CODEC_TRACE("hash = %s\n", hash);
    if (err == IN_CORE_FIPS_E) {
        CODEC_TRACE("In core integrity hash check failure, copy above hash\n");
        CODEC_TRACE("into verifyCore[] in fips_test.c and rebuild\n");
    }
}
#endif

static int sqlcipher_wolf_add_random(void *ctx, void *buffer, int length) {
  (void)ctx;
  (void)buffer;
  (void)length;
  /* not used */
  return SQLITE_OK;
}

/* generate a defined number of random bytes */
static WC_RNG gRng;
static int    gRngInit = 0;
static int sqlcipher_wolf_random(void *ctx, void *buffer, int length) {
  int ret = -1;
  if (!gRngInit) {
    ret = wc_InitRng(&gRng);
    if (ret == 0) {
      gRngInit = 1;
    }
  }
  if (gRngInit) {
      ret = wc_RNG_GenerateBlock(&gRng, buffer, length);
  }
  return (ret == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static const char* sqlcipher_wolf_get_provider_name(void *ctx) {
  return "wolfssl";
}

static const char* sqlcipher_wolf_get_provider_version(void *ctx) {
    return LIBWOLFSSL_VERSION_STRING;
}

static int sqlcipher_wolf_hmac(void *ctx, int algorithm, unsigned char *hmac_key,
    int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  int ret;
  Hmac hmac_context;
  if(in == NULL) return SQLITE_ERROR;
  if (wc_HmacInit(&hmac_context, NULL, INVALID_DEVID) != 0) return SQLITE_ERROR;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      ret = wc_HmacSetKey(&hmac_context, WC_SHA, hmac_key, key_sz);
      break;
    case SQLCIPHER_HMAC_SHA256:
      ret = wc_HmacSetKey(&hmac_context, WC_SHA256, hmac_key, key_sz);
      break;
    case SQLCIPHER_HMAC_SHA512:
      ret = wc_HmacSetKey(&hmac_context, WC_SHA512, hmac_key, key_sz);
      break;
    default:
      ret = SQLITE_ERROR;
  }
  if (ret == 0)
    ret = wc_HmacUpdate(&hmac_context, in, in_sz);
  if (ret == 0 && in2 != NULL)
    ret = wc_HmacUpdate(&hmac_context, in2, in2_sz);
  if (ret == 0)
    ret = wc_HmacFinal(&hmac_context, out);
  wc_HmacFree(&hmac_context);
  return (ret == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_wolf_kdf(void *ctx, int algorithm, const unsigned char *pass,
    int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int ret;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      ret = wc_PBKDF2(key, pass, pass_sz, salt, salt_sz, workfactor, key_sz, WC_SHA);
      break;
    case SQLCIPHER_HMAC_SHA256:
      ret = wc_PBKDF2(key, pass, pass_sz, salt, salt_sz, workfactor, key_sz, WC_SHA256);
      break;
    case SQLCIPHER_HMAC_SHA512:
      ret = wc_PBKDF2(key, pass, pass_sz, salt, salt_sz, workfactor, key_sz, WC_SHA512);
      break;
    default:
      ret = SQLITE_ERROR;
  }
  return (ret == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_wolf_cipher(void *ctx, int mode, unsigned char *key,
    int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int ret;
  Aes aes;
  if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return SQLITE_ERROR;
  ret = wc_AesSetKey(&aes, key, key_sz, iv, 
    mode == CIPHER_ENCRYPT ? AES_ENCRYPTION : AES_DECRYPTION);
  if (ret == 0) {
      if (mode == CIPHER_ENCRYPT)
        ret = wc_AesCbcEncrypt(&aes, out, in, in_sz);
      else
        ret = wc_AesCbcDecrypt(&aes, out, in, in_sz);
  }
  wc_AesFree(&aes);
  return (ret == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static const char* sqlcipher_wolf_get_cipher(void *ctx) {
  return "aes-256-cbc";
}

static int sqlcipher_wolf_get_key_sz(void *ctx) {
  return AES_256_KEY_SIZE;
}

static int sqlcipher_wolf_get_iv_sz(void *ctx) {
  return AES_BLOCK_SIZE;
}

static int sqlcipher_wolf_get_block_sz(void *ctx) {
  return AES_BLOCK_SIZE;
}

static int sqlcipher_wolf_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      return WC_SHA_DIGEST_SIZE;
    case SQLCIPHER_HMAC_SHA256:
      return WC_SHA256_DIGEST_SIZE;
    case SQLCIPHER_HMAC_SHA512:
      return WC_SHA512_DIGEST_SIZE;
    default:
      return 0;
  }
}

static int sqlcipher_wolf_ctx_init(void **ctx) {
  if (wolfCrypt_Init() != 0) {
      return SQLITE_ERROR;
  }
#ifdef HAVE_FIPS
  wolfCrypt_SetCb_fips(wcFipsCb);
#endif
  return SQLITE_OK;
}

static int sqlcipher_wolf_ctx_free(void **ctx) {
  if (gRngInit) {
      wc_FreeRng(&gRng);
      gRngInit = 0;
  }

  wolfCrypt_Cleanup();
  return SQLITE_OK;
}

static int sqlcipher_wolf_fips_status(void *ctx) {
#ifdef HAVE_FIPS
    if (wolfCrypt_GetStatus_fips() == 0) {
        return 1; /* FIPS available and valid */
    }
#endif
  return 0;
}

int sqlcipher_wolf_setup(sqlcipher_provider *p) {
  p->random = sqlcipher_wolf_random;
  p->get_provider_name = sqlcipher_wolf_get_provider_name;
  p->hmac = sqlcipher_wolf_hmac;
  p->kdf = sqlcipher_wolf_kdf;
  p->cipher = sqlcipher_wolf_cipher;
  p->get_cipher = sqlcipher_wolf_get_cipher;
  p->get_key_sz = sqlcipher_wolf_get_key_sz;
  p->get_iv_sz = sqlcipher_wolf_get_iv_sz;
  p->get_block_sz = sqlcipher_wolf_get_block_sz;
  p->get_hmac_sz = sqlcipher_wolf_get_hmac_sz;
  p->ctx_init = sqlcipher_wolf_ctx_init;
  p->ctx_free = sqlcipher_wolf_ctx_free;
  p->add_random = sqlcipher_wolf_add_random;
  p->fips_status = sqlcipher_wolf_fips_status;
  p->get_provider_version = sqlcipher_wolf_get_provider_version;
  return SQLITE_OK;
}

#endif /* SQLCIPHER_CRYPTO_WOLFSSL */
#endif
/* END SQLCIPHER */
