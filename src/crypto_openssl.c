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
#ifdef SQLCIPHER_CRYPTO_OPENSSL
#include "sqliteInt.h"
#include "crypto.h"
#include "sqlcipher.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

static unsigned int openssl_init_count = 0;

#if (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
static HMAC_CTX *HMAC_CTX_new(void)
{
  HMAC_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));
  if (ctx != NULL) {
    HMAC_CTX_init(ctx);
  }
  return ctx;
}

/* Per 1.1.0 (https://wiki.openssl.org/index.php/1.1_API_Changes)
   HMAC_CTX_free should call HMAC_CTX_cleanup, then EVP_MD_CTX_Cleanup.
   HMAC_CTX_cleanup internally calls EVP_MD_CTX_cleanup so these
   calls are not needed. */
static void HMAC_CTX_free(HMAC_CTX *ctx)
{
  if (ctx != NULL) {
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
  }
}
#endif

static int sqlcipher_openssl_add_random(void *ctx, void *buffer, int length) {
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_add_random: entering SQLCIPHER_MUTEX_PROVIDER_RAND");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_add_random: entered SQLCIPHER_MUTEX_PROVIDER_RAND");
#endif
  RAND_add(buffer, length, 0);
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_add_random: leaving SQLCIPHER_MUTEX_PROVIDER_RAND");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_add_random: left SQLCIPHER_MUTEX_PROVIDER_RAND");
#endif
  return SQLITE_OK;
}

#define OPENSSL_CIPHER EVP_aes_256_cbc()


/* activate and initialize sqlcipher. Most importantly, this will automatically
   intialize OpenSSL's EVP system if it hasn't already be externally. Note that 
   this function may be called multiple times as new codecs are intiialized. 
   Thus it performs some basic counting to ensure that only the last and final
   sqlcipher_openssl_deactivate() will free the EVP structures. 
*/
static int sqlcipher_openssl_activate(void *ctx) {
  /* initialize openssl and increment the internal init counter
     but only if it hasn't been initalized outside of SQLCipher by this program 
     e.g. on startup */
 
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_activate: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_activate: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");

#ifdef SQLCIPHER_FIPS
  if(!FIPS_mode()){
    if(!FIPS_mode_set(1)){
      unsigned long err = 0;
      ERR_load_crypto_strings();
#ifdef __ANDROID__
      while((err = ERR_get_error()) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "sqlcipher","error: %lx. %s.", err, ERR_error_string(err, NULL));
      }
#else
      ERR_print_errors_fp(stderr);
#endif
    }
  }
#endif

  openssl_init_count++; 
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_activate: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_activate: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");
  return SQLITE_OK;
}

/* deactivate SQLCipher, most imporantly decremeting the activation count and
   freeing the EVP structures on the final deactivation to ensure that 
   OpenSSL memory is cleaned up */
static int sqlcipher_openssl_deactivate(void *ctx) {
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_deactivate: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_deactivate: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");

  openssl_init_count--;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_deactivate: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_deactivate: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE");
  return SQLITE_OK;
}

static const char* sqlcipher_openssl_get_provider_name(void *ctx) {
  return "openssl";
}

static const char* sqlcipher_openssl_get_provider_version(void *ctx) {
  return OPENSSL_VERSION_TEXT;
}

/* generate a defined number of random bytes */
static int sqlcipher_openssl_random (void *ctx, void *buffer, int length) {
  int rc = 0;
  /* concurrent calls to RAND_bytes can cause a crash under some openssl versions when a 
     naive application doesn't use CRYPTO_set_locking_callback and
     CRYPTO_THREADID_set_callback to ensure openssl thread safety. 
     This is simple workaround to prevent this common crash
     but a more proper solution is that applications setup platform-appropriate
     thread saftey in openssl externally */
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_random: entering SQLCIPHER_MUTEX_PROVIDER_RAND");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_random: entered SQLCIPHER_MUTEX_PROVIDER_RAND");
#endif
  rc = RAND_bytes((unsigned char *)buffer, length);
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_random: leaving SQLCIPHER_MUTEX_PROVIDER_RAND");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, "sqlcipher_openssl_random: left SQLCIPHER_MUTEX_PROVIDER_RAND");
#endif
  return (rc == 1) ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_openssl_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  unsigned int outlen;
  int rc = SQLITE_OK;
  HMAC_CTX* hctx = NULL;

  if(in == NULL) goto error;

  hctx = HMAC_CTX_new();
  if(hctx == NULL) goto error;

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      if(!HMAC_Init_ex(hctx, hmac_key, key_sz, EVP_sha1(), NULL)) goto error;
      break;
    case SQLCIPHER_HMAC_SHA256:
      if(!HMAC_Init_ex(hctx, hmac_key, key_sz, EVP_sha256(), NULL)) goto error;
      break;
    case SQLCIPHER_HMAC_SHA512:
      if(!HMAC_Init_ex(hctx, hmac_key, key_sz, EVP_sha512(), NULL)) goto error;
      break;
    default:
      goto error;
  }

  if(!HMAC_Update(hctx, in, in_sz)) goto error;
  if(in2 != NULL) {
    if(!HMAC_Update(hctx, in2, in2_sz)) goto error;
  }
  if(!HMAC_Final(hctx, out, &outlen)) goto error;
  
  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if(hctx) HMAC_CTX_free(hctx);
  return rc;
}

static int sqlcipher_openssl_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc = SQLITE_OK; 

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      if(!PKCS5_PBKDF2_HMAC((const char *)pass, pass_sz, salt, salt_sz, workfactor, EVP_sha1(), key_sz, key)) goto error;
      break;
    case SQLCIPHER_HMAC_SHA256:
      if(!PKCS5_PBKDF2_HMAC((const char *)pass, pass_sz, salt, salt_sz, workfactor, EVP_sha256(), key_sz, key)) goto error;
      break;
    case SQLCIPHER_HMAC_SHA512:
      if(!PKCS5_PBKDF2_HMAC((const char *)pass, pass_sz, salt, salt_sz, workfactor, EVP_sha512(), key_sz, key)) goto error;
      break;
    default:
      return SQLITE_ERROR;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  return rc;
}

static int sqlcipher_openssl_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int tmp_csz, csz, rc = SQLITE_OK;
  EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
  if(ectx == NULL) goto error;
  if(!EVP_CipherInit_ex(ectx, OPENSSL_CIPHER, NULL, NULL, NULL, mode)) goto error;
  if(!EVP_CIPHER_CTX_set_padding(ectx, 0)) goto error; /* no padding */
  if(!EVP_CipherInit_ex(ectx, NULL, NULL, key, iv, mode)) goto error;
  if(!EVP_CipherUpdate(ectx, out, &tmp_csz, in, in_sz)) goto error;
  csz = tmp_csz;  
  out += tmp_csz;
  if(!EVP_CipherFinal_ex(ectx, out, &tmp_csz)) goto error;
  csz += tmp_csz;
  assert(in_sz == csz);

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if(ectx) EVP_CIPHER_CTX_free(ectx);
  return rc; 
}

static const char* sqlcipher_openssl_get_cipher(void *ctx) {
  return OBJ_nid2sn(EVP_CIPHER_nid(OPENSSL_CIPHER));
}

static int sqlcipher_openssl_get_key_sz(void *ctx) {
  return EVP_CIPHER_key_length(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_iv_sz(void *ctx) {
  return EVP_CIPHER_iv_length(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_block_sz(void *ctx) {
  return EVP_CIPHER_block_size(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      return EVP_MD_size(EVP_sha1());
      break;
    case SQLCIPHER_HMAC_SHA256:
      return EVP_MD_size(EVP_sha256());
      break;
    case SQLCIPHER_HMAC_SHA512:
      return EVP_MD_size(EVP_sha512());
      break;
    default:
      return 0;
  }
}

static int sqlcipher_openssl_ctx_init(void **ctx) {
  return sqlcipher_openssl_activate(*ctx);
}

static int sqlcipher_openssl_ctx_free(void **ctx) {
  return sqlcipher_openssl_deactivate(NULL);
}

static int sqlcipher_openssl_fips_status(void *ctx) {
#ifdef SQLCIPHER_FIPS  
  return FIPS_mode();
#else
  return 0;
#endif
}

int sqlcipher_openssl_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_openssl_activate;  
  p->deactivate = sqlcipher_openssl_deactivate;
  p->get_provider_name = sqlcipher_openssl_get_provider_name;
  p->random = sqlcipher_openssl_random;
  p->hmac = sqlcipher_openssl_hmac;
  p->kdf = sqlcipher_openssl_kdf;
  p->cipher = sqlcipher_openssl_cipher;
  p->get_cipher = sqlcipher_openssl_get_cipher;
  p->get_key_sz = sqlcipher_openssl_get_key_sz;
  p->get_iv_sz = sqlcipher_openssl_get_iv_sz;
  p->get_block_sz = sqlcipher_openssl_get_block_sz;
  p->get_hmac_sz = sqlcipher_openssl_get_hmac_sz;
  p->ctx_init = sqlcipher_openssl_ctx_init;
  p->ctx_free = sqlcipher_openssl_ctx_free;
  p->add_random = sqlcipher_openssl_add_random;
  p->fips_status = sqlcipher_openssl_fips_status;
  p->get_provider_version = sqlcipher_openssl_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
