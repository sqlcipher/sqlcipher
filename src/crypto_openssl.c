#ifdef SQLCIPHER_CRYPTO_OPENSSL
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct {
  EVP_CIPHER *evp_cipher;
} openssl_ctx;


static unsigned int openssl_external_init = 0;
static unsigned int openssl_init_count = 0;

/* activate and initialize sqlcipher. Most importantly, this will automatically
   intialize OpenSSL's EVP system if it hasn't already be externally. Note that 
   this function may be called multiple times as new codecs are intiialized. 
   Thus it performs some basic counting to ensure that only the last and final
   sqlcipher_deactivate() will free the EVP structures. 
*/
void sqlcipher_activate(void *ctx) {
  sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));

  /* we'll initialize openssl and increment the internal init counter
     but only if it hasn't been initalized outside of SQLCipher by this program 
     e.g. on startup */
  if(openssl_init_count == 0 && EVP_get_cipherbyname(CIPHER) != NULL) {
    openssl_external_init = 1;
  }

  if(openssl_external_init == 0) {
    if(openssl_init_count == 0)  {
      OpenSSL_add_all_algorithms();
    }
    openssl_init_count++; 
  } 
  sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
}

/* deactivate SQLCipher, most imporantly decremeting the activation count and
   freeing the EVP structures on the final deactivation to ensure that 
   OpenSSL memory is cleaned up */
void sqlcipher_deactivate(void *ctx) {
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

/* generate a defined number of pseudorandom bytes */
int sqlcipher_random (void *ctx, void *buffer, int length) {
  return RAND_bytes((unsigned char *)buffer, length);
}

int sqlcipher_hmac(void *ctx, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  HMAC_CTX hctx;
  HMAC_CTX_init(&hctx);
  HMAC_Init_ex(&hctx, hmac_key, key_sz, EVP_sha1(), NULL);
  HMAC_Update(&hctx, in, in_sz);
  HMAC_Update(&hctx, in2, in2_sz);
  HMAC_Final(&hctx, out, NULL);
  HMAC_CTX_cleanup(&hctx);
  return SQLITE_OK; 
}

int sqlcipher_kdf(void *ctx, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  PKCS5_PBKDF2_HMAC_SHA1(pass, pass_sz, salt, salt_sz, workfactor, key_sz, key); 
  return SQLITE_OK; 
}

int sqlcipher_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
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

int sqlcipher_set_cipher(void *ctx, const char *cipher_name) {
  openssl_ctx *o_ctx = (openssl_ctx *)ctx;
  o_ctx->evp_cipher = (EVP_CIPHER *) EVP_get_cipherbyname(cipher_name);
  return SQLITE_OK;
}

const char* sqlcipher_get_cipher(void *ctx) {
  return EVP_CIPHER_name(((openssl_ctx *)ctx)->evp_cipher);
}

int sqlcipher_get_key_sz(void *ctx) {
  return EVP_CIPHER_key_length(((openssl_ctx *)ctx)->evp_cipher);
}

int sqlcipher_get_iv_sz(void *ctx) {
  return EVP_CIPHER_iv_length(((openssl_ctx *)ctx)->evp_cipher);
}

int sqlcipher_get_block_sz(void *ctx) {
  return EVP_CIPHER_block_size(((openssl_ctx *)ctx)->evp_cipher);
}

int sqlcipher_get_hmac_sz(void *ctx) {
  return EVP_MD_size(EVP_sha1());
}

int sqlcipher_ctx_copy(void *target_ctx, void *source_ctx) {
  memcpy(target_ctx, source_ctx, sizeof(openssl_ctx));
  return SQLITE_OK;
}

int sqlcipher_ctx_cmp(void *c1, void *c2) {
  return ((openssl_ctx *)c1)->evp_cipher == ((openssl_ctx *)c2)->evp_cipher;
}

int sqlcipher_ctx_init(void **ctx) {
  *ctx = sqlcipher_malloc(sizeof(openssl_ctx));
  if(*ctx == NULL) return SQLITE_NOMEM;
  return SQLITE_OK;
}

int sqlcipher_ctx_free(void **ctx) {
  sqlcipher_free(*ctx, sizeof(openssl_ctx));
  return SQLITE_OK;
}
#endif
