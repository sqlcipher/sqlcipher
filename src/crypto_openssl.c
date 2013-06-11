#ifdef SQLCIPHER_CRYPTO_OPENSSL
#include "sqliteInt.h"
#include "crypto.h"
#include "sqlcipher.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct {
  EVP_CIPHER *evp_cipher;
} openssl_ctx;


static unsigned int openssl_external_init = 0;
static unsigned int openssl_init_count = 0;


static int sqlcipher_openssl_add_random(void *ctx, void *buffer, int length) {
  RAND_add(buffer, length, 0);
  return SQLITE_OK;
}

/* activate and initialize sqlcipher. Most importantly, this will automatically
   intialize OpenSSL's EVP system if it hasn't already be externally. Note that 
   this function may be called multiple times as new codecs are intiialized. 
   Thus it performs some basic counting to ensure that only the last and final
   sqlcipher_openssl_deactivate() will free the EVP structures. 
*/
static int sqlcipher_openssl_activate(void *ctx) {
  /* we'll initialize openssl and increment the internal init counter
     but only if it hasn't been initalized outside of SQLCipher by this program 
     e.g. on startup */
  if(openssl_init_count == 0 && EVP_get_cipherbyname(CIPHER) != NULL) {
    openssl_external_init = 1;
  }

  if(openssl_external_init == 0) {
    if(openssl_init_count == 0)  {
      OpenSSL_add_all_algorithms();
      if(sqlcipher_openssl_add_random(ctx, &ctx, sizeof(openssl_ctx *)) != SQLITE_OK) {
        return SQLITE_ERROR;
      }
    }
    openssl_init_count++; 
  } 
}

/* deactivate SQLCipher, most imporantly decremeting the activation count and
   freeing the EVP structures on the final deactivation to ensure that 
   OpenSSL memory is cleaned up */
static int sqlcipher_openssl_deactivate(void *ctx) {
  sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
  /* If it is initialized externally, then the init counter should never be greater than zero.
     This should prevent SQLCipher from "cleaning up" openssl 
     when something else in the program might be using it. */
  if(openssl_external_init == 0) {
    openssl_init_count--;
    /* if the counter reaches zero after it's decremented release EVP memory
       Note: this code will only be reached if OpensSSL_add_all_algorithms()
       is called by SQLCipher internally. */
    if(openssl_init_count == 0) {
      EVP_cleanup();
    }
  }
  sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
}

static const char* sqlcipher_openssl_get_provider_name(void *ctx) {
  return "openssl";
}

/* generate a defined number of pseudorandom bytes */
static int sqlcipher_openssl_random (void *ctx, void *buffer, int length) {
  RAND_bytes((unsigned char *)buffer, length);
  return SQLITE_OK;
}

static int sqlcipher_openssl_hmac(void *ctx, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  HMAC_CTX hctx;
  int outlen;
  HMAC_CTX_init(&hctx);
  HMAC_Init_ex(&hctx, hmac_key, key_sz, EVP_sha1(), NULL);
  HMAC_Update(&hctx, in, in_sz);
  HMAC_Update(&hctx, in2, in2_sz);
  HMAC_Final(&hctx, out, &outlen);
  HMAC_CTX_cleanup(&hctx);
  return SQLITE_OK; 
}

static int sqlcipher_openssl_kdf(void *ctx, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  unsigned long random_buffer_sz = 256;
  char random_buffer[random_buffer_sz];
  
  PKCS5_PBKDF2_HMAC_SHA1(pass, pass_sz, salt, salt_sz, workfactor, key_sz, key);
  PKCS5_PBKDF2_HMAC_SHA1(key, key_sz, salt, salt_sz, 1, random_buffer_sz, random_buffer);
  sqlcipher_openssl_add_random(ctx, random_buffer, random_buffer_sz);
  return SQLITE_OK; 
}

static int sqlcipher_openssl_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  EVP_CIPHER_CTX ectx;
  int tmp_csz, csz;
 
  EVP_CipherInit(&ectx, ((openssl_ctx *)ctx)->evp_cipher, NULL, NULL, mode);
  EVP_CIPHER_CTX_set_padding(&ectx, 0); // no padding
  EVP_CipherInit(&ectx, NULL, key, iv, mode);
  EVP_CipherUpdate(&ectx, out, &tmp_csz, in, in_sz);
  csz = tmp_csz;  
  out += tmp_csz;
  EVP_CipherFinal(&ectx, out, &tmp_csz);
  csz += tmp_csz;
  EVP_CIPHER_CTX_cleanup(&ectx);
  assert(in_sz == csz);
  return SQLITE_OK; 
}

static int sqlcipher_openssl_set_cipher(void *ctx, const char *cipher_name) {
  openssl_ctx *o_ctx = (openssl_ctx *)ctx;
  o_ctx->evp_cipher = (EVP_CIPHER *) EVP_get_cipherbyname(cipher_name);
  return SQLITE_OK;
}

static const char* sqlcipher_openssl_get_cipher(void *ctx) {
  return EVP_CIPHER_name(((openssl_ctx *)ctx)->evp_cipher);
}

static int sqlcipher_openssl_get_key_sz(void *ctx) {
  return EVP_CIPHER_key_length(((openssl_ctx *)ctx)->evp_cipher);
}

static int sqlcipher_openssl_get_iv_sz(void *ctx) {
  return EVP_CIPHER_iv_length(((openssl_ctx *)ctx)->evp_cipher);
}

static int sqlcipher_openssl_get_block_sz(void *ctx) {
  return EVP_CIPHER_block_size(((openssl_ctx *)ctx)->evp_cipher);
}

static int sqlcipher_openssl_get_hmac_sz(void *ctx) {
  return EVP_MD_size(EVP_sha1());
}

static int sqlcipher_openssl_ctx_copy(void *target_ctx, void *source_ctx) {
  memcpy(target_ctx, source_ctx, sizeof(openssl_ctx));
  return SQLITE_OK;
}

static int sqlcipher_openssl_ctx_cmp(void *c1, void *c2) {
  return ((openssl_ctx *)c1)->evp_cipher == ((openssl_ctx *)c2)->evp_cipher;
}

static int sqlcipher_openssl_ctx_init(void **ctx) {
  *ctx = sqlcipher_malloc(sizeof(openssl_ctx));
  if(*ctx == NULL) return SQLITE_NOMEM;
  sqlcipher_openssl_activate(*ctx);
  return SQLITE_OK;
}

static int sqlcipher_openssl_ctx_free(void **ctx) {
  sqlcipher_openssl_deactivate(*ctx);
  sqlcipher_free(*ctx, sizeof(openssl_ctx));
  return SQLITE_OK;
}

int sqlcipher_openssl_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_openssl_activate;  
  p->deactivate = sqlcipher_openssl_deactivate;
  p->get_provider_name = sqlcipher_openssl_get_provider_name;
  p->random = sqlcipher_openssl_random;
  p->hmac = sqlcipher_openssl_hmac;
  p->kdf = sqlcipher_openssl_kdf;
  p->cipher = sqlcipher_openssl_cipher;
  p->set_cipher = sqlcipher_openssl_set_cipher;
  p->get_cipher = sqlcipher_openssl_get_cipher;
  p->get_key_sz = sqlcipher_openssl_get_key_sz;
  p->get_iv_sz = sqlcipher_openssl_get_iv_sz;
  p->get_block_sz = sqlcipher_openssl_get_block_sz;
  p->get_hmac_sz = sqlcipher_openssl_get_hmac_sz;
  p->ctx_copy = sqlcipher_openssl_ctx_copy;
  p->ctx_cmp = sqlcipher_openssl_ctx_cmp;
  p->ctx_init = sqlcipher_openssl_ctx_init;
  p->ctx_free = sqlcipher_openssl_ctx_free;
  p->add_random = sqlcipher_openssl_add_random;
}

#endif
