/*
** SQLCipher
** http://sqlcipher.net
**
** mbedtls support implementation by Jichan(development@jc-lab.net, ablog.jc-lab.net)
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
/* BEGIN SQLCIPHER USING MBED-TLS */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_MBEDTLS
#include "sqliteInt.h"
#include "crypto.h"
#include "sqlcipher.h"

#include <mbedtls/version.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

typedef struct {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const mbedtls_cipher_info_t *cipher_info;
} mbedtls_ctx;

static int sqlcipher_mbedtls_add_random(void *ctx, void *buffer, int length) {
    mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
    mbedtls_ctr_drbg_random_with_add(&ctximpl->ctr_drbg, (unsigned char*)buffer, length, NULL, 0);
  return SQLITE_OK;
}

/* activate and initialize sqlcipher. Note that this function may be called
   multiple times as new codecs are initialized. Thus it performs some basic
   counting to ensure that only the last and final sqlcipher_mbedtls_deactivate()
   will free the global mbedtls structures.
*/
static int sqlcipher_mbedtls_activate(void *ctx) {
  return SQLITE_OK;
}

/* deactivate SQLCipher, most imporantly decremeting the activation count and
   freeing the mbedtls structures on the final deactivation to ensure that
   mbedtls memory is cleaned up */
static int sqlcipher_mbedtls_deactivate(void *ctx) {
  return SQLITE_OK;
}

static const char* sqlcipher_mbedtls_get_provider_name(void *ctx) {
  return "mbedtls";
}

static const char* sqlcipher_mbedtls_get_provider_version(void *ctx) {
  return MBEDTLS_VERSION_STRING_FULL;
}

/* generate a defined number of random bytes */
static int sqlcipher_mbedtls_random (void *ctx, void *buffer, int length) {
    mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
    int rc = mbedtls_ctr_drbg_random(&ctximpl->ctr_drbg, (unsigned char*)buffer, length);
    return (rc == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_mbedtls_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  unsigned int outlen;
  int rc = SQLITE_OK;
  int librc;
  mbedtls_md_context_t md_ctx;
  mbedtls_md_type_t md_type;

  mbedtls_md_init(&md_ctx);

  if(in == NULL) goto error;

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
        md_type = MBEDTLS_MD_SHA1;
      break;
    case SQLCIPHER_HMAC_SHA256:
        md_type = MBEDTLS_MD_SHA256;
      break;
    case SQLCIPHER_HMAC_SHA512:
        md_type = MBEDTLS_MD_SHA512;
      break;
    default:
      goto error;
  }

  librc = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1); //use hmac
  if (librc != 0)
  {
	  goto error;
  }
  librc = mbedtls_md_hmac_starts(&md_ctx, hmac_key, key_sz);
  if (librc != 0)
  {
	  goto error;
  }
  librc = mbedtls_md_hmac_update(&md_ctx, in, in_sz);
  if (librc != 0)
  {
	  goto error;
  }
  if(in2 != NULL) {
	  librc = mbedtls_md_hmac_update(&md_ctx, in2, in2_sz);
	  if (librc != 0)
	  {
		  goto error;
	  }
  }
  librc = mbedtls_md_hmac_finish(&md_ctx, out);
  if (librc != 0)
  {
	  goto error;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  mbedtls_md_free(&md_ctx);
  return rc;
}

static int sqlcipher_mbedtls_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc = SQLITE_OK;
  int librc;
  mbedtls_md_context_t md_ctx;
  mbedtls_md_type_t md_type;

  mbedtls_md_init(&md_ctx);

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
        md_type = MBEDTLS_MD_SHA1;
      break;
    case SQLCIPHER_HMAC_SHA256:
        md_type = MBEDTLS_MD_SHA256;
      break;
    case SQLCIPHER_HMAC_SHA512:
        md_type = MBEDTLS_MD_SHA512;
      break;
    default:
      return SQLITE_ERROR;
  }

  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1);
  librc = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, (const unsigned char*)pass, pass_sz, (const unsigned char*)salt, salt_sz, workfactor, key_sz, key);
  if(librc == 0)
      rc = SQLITE_OK;
  else
      goto error;

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  mbedtls_md_free(&md_ctx);
  return rc;
}

static int sqlcipher_mbedtls_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
  int rc = SQLITE_OK;
  int librc;
  int csz = 0;
  size_t olen = 0;
  mbedtls_cipher_context_t cipher_ctx;

  mbedtls_cipher_init(&cipher_ctx);
  if((librc = mbedtls_cipher_setup(&cipher_ctx, ctximpl->cipher_info)) != 0)
  {
    return SQLITE_ERROR;
  }
  if ((librc = mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_PADDING_NONE)) != 0)
  {
	return SQLITE_ERROR;
  }
  if((librc = mbedtls_cipher_setkey(&cipher_ctx, key, key_sz * 8, mode ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT)) != 0)
  {
    goto error;
  }
  if((librc = mbedtls_cipher_set_iv(&cipher_ctx, iv, ctximpl->cipher_info->iv_size)) != 0)
  {
    goto error;
  }
  if((librc = mbedtls_cipher_crypt(&cipher_ctx, iv, ctximpl->cipher_info->iv_size, in, in_sz, out, &olen)) != 0)
  {
    goto error;
  }
  csz = olen;
  out += olen;
  if((librc = mbedtls_cipher_finish(&cipher_ctx, out, &olen)) != 0)
  {
    goto error;
  }
  csz += olen;

  assert(in_sz == csz);

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  mbedtls_cipher_free(&cipher_ctx);
  return rc;
}

static const char* sqlcipher_mbedtls_get_cipher(void *ctx) {
    mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
    if(ctximpl->cipher_info)
        return ctximpl->cipher_info->name;
    return NULL;
}

static int sqlcipher_mbedtls_get_key_sz(void *ctx) {
    mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
    if(ctximpl->cipher_info)
        return ctximpl->cipher_info->key_bitlen / 8;
    return 0;
}

static int sqlcipher_mbedtls_get_iv_sz(void *ctx) {
    mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
    if(ctximpl->cipher_info)
        return ctximpl->cipher_info->iv_size;
    return 0;
}

static int sqlcipher_mbedtls_get_block_sz(void *ctx) {
    mbedtls_ctx *ctximpl = (mbedtls_ctx*)ctx;
    if(ctximpl->cipher_info)
        return ctximpl->cipher_info->block_size;
    return 0;
}

static int sqlcipher_mbedtls_get_hmac_sz(void *ctx, int algorithm) {
  int md_size_ret = 0;
  mbedtls_md_context_t md_ctx;
  mbedtls_md_type_t md_type;

  mbedtls_md_init(&md_ctx);

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
        md_type = MBEDTLS_MD_SHA1;
      break;
    case SQLCIPHER_HMAC_SHA256:
        md_type = MBEDTLS_MD_SHA256;
      break;
    case SQLCIPHER_HMAC_SHA512:
        md_type = MBEDTLS_MD_SHA512;
      break;
    default:
      return 0;
  }

  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1);

  md_size_ret = mbedtls_md_get_size(md_ctx.md_info);

  mbedtls_md_free(&md_ctx);

  return md_size_ret;
}

static int sqlcipher_mbedtls_ctx_copy(void *target_ctx, void *source_ctx) {
  memcpy(target_ctx, source_ctx, sizeof(mbedtls_ctx));
  return SQLITE_OK;
}

static int sqlcipher_mbedtls_ctx_cmp(void *c1, void *c2) {
  return ((mbedtls_ctx *)c1)->cipher_info == ((mbedtls_ctx *)c2)->cipher_info;
}

static int sqlcipher_mbedtls_ctx_init(void **ctx) {
  int librc;
  mbedtls_ctx *o_ctx;
  char *personalization = "sqlcipher";

  *ctx = sqlcipher_malloc(sizeof(mbedtls_ctx));
  if(*ctx == NULL) return SQLITE_NOMEM;
  sqlcipher_mbedtls_activate(*ctx);
  
  o_ctx = (mbedtls_ctx *)*ctx;
  mbedtls_entropy_init(&o_ctx->entropy);
  mbedtls_ctr_drbg_init(&o_ctx->ctr_drbg);

  o_ctx->cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);

  librc = mbedtls_ctr_drbg_seed( &o_ctx->ctr_drbg , mbedtls_entropy_func, &o_ctx->entropy,
                     (const unsigned char *) personalization,
                     strlen( personalization ) );
  return (librc == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_mbedtls_ctx_free(void **ctx) {
  mbedtls_ctx *ctximpl = (mbedtls_ctx*)*ctx;
  mbedtls_ctr_drbg_free(&ctximpl->ctr_drbg);
  mbedtls_entropy_free(&ctximpl->entropy);
  sqlcipher_mbedtls_deactivate(*ctx);
  sqlcipher_free(*ctx, sizeof(mbedtls_ctx));
  return SQLITE_OK;
}

static int sqlcipher_mbedtls_fips_status(void *ctx) {
  return 0;
}

int sqlcipher_mbedtls_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_mbedtls_activate;  
  p->deactivate = sqlcipher_mbedtls_deactivate;
  p->get_provider_name = sqlcipher_mbedtls_get_provider_name;
  p->random = sqlcipher_mbedtls_random;
  p->hmac = sqlcipher_mbedtls_hmac;
  p->kdf = sqlcipher_mbedtls_kdf;
  p->cipher = sqlcipher_mbedtls_cipher;
  p->get_cipher = sqlcipher_mbedtls_get_cipher;
  p->get_key_sz = sqlcipher_mbedtls_get_key_sz;
  p->get_iv_sz = sqlcipher_mbedtls_get_iv_sz;
  p->get_block_sz = sqlcipher_mbedtls_get_block_sz;
  p->get_hmac_sz = sqlcipher_mbedtls_get_hmac_sz;
  p->ctx_copy = sqlcipher_mbedtls_ctx_copy;
  p->ctx_cmp = sqlcipher_mbedtls_ctx_cmp;
  p->ctx_init = sqlcipher_mbedtls_ctx_init;
  p->ctx_free = sqlcipher_mbedtls_ctx_free;
  p->add_random = sqlcipher_mbedtls_add_random;
  p->fips_status = sqlcipher_mbedtls_fips_status;
  p->get_provider_version = sqlcipher_mbedtls_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER USING MBED-TLS */
