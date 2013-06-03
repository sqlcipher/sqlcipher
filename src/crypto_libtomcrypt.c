#ifdef SQLCIPHER_CRYPTO_LIBTOMCRYPTO
#include <tomcrypt.h>

void sqlcipher_activate(void *ctx) {
  register_prng(&fortuna_desc);
  register_cipher(&rijndael_desc);
  register_hash(&sha256_desc);
  register_hash(&sha1_desc);
}

void sqlcipher_deactivate(void *ctx) {
}

int sqlcipher_random(void *ctx, void *buffer, int length) {
  prng_state prng;
  int random_value;
  int random_buffer_sz = 256;
  char random_buffer[random_buffer_sz];

  if(fortuna_start(&prng) != CRYPT_OK) return SQLITE_ERROR;
  sqlite3_randomness(sizeof(random_value), &random_value);
  sqlite3_snprintf(random_buffer_sz, random_buffer, "%d", random_value);
  if(fortuna_add_entropy(random_buffer, random_buffer_sz, &prng) != CRYPT_OK) return SQLITE_ERROR;
  if(fortuna_ready(&prng) != CRYPT_OK) return SQLITE_ERROR;
  fortuna_read(buffer, length, &prng);
  fortuna_done(&prng);
  return SQLITE_OK;
}

int sqlcipher_hmac(void *ctx, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
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

int sqlcipher_kdf(void *ctx, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc, hash_idx;
  unsigned long outlen = key_sz;

  hash_idx = find_hash("sha1");
  if((rc = pkcs_5_alg2(pass, pass_sz, salt, salt_sz,
                       workfactor, hash_idx, key, &outlen)) != CRYPT_OK) return SQLITE_ERROR;
  return SQLITE_OK;
}

int sqlcipher_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int rc, cipher_idx, hash_idx;
  symmetric_CBC cbc;

  if((cipher_idx = find_cipher(sqlcipher_get_cipher(ctx))) == -1) return SQLITE_ERROR;
  if((hash_idx = find_hash("sha256")) == -1) return SQLITE_ERROR;
  if((rc = cbc_start(cipher_idx, iv, key, key_sz, 0, &cbc)) != CRYPT_OK) return SQLITE_ERROR;
  rc = mode == 1 ? cbc_encrypt(in, out, in_sz, &cbc) : cbc_decrypt(in, out, in_sz, &cbc);
  if(rc != CRYPT_OK) return SQLITE_ERROR;
  cbc_done(&cbc);
  return SQLITE_OK;
}

int sqlcipher_set_cipher(void *ctx, const char *cipher_name) {
  return SQLITE_OK;
}

const char* sqlcipher_get_cipher(void *ctx) {
  return "rijndael";
}

int sqlcipher_get_key_sz(void *ctx) {
  int cipher_idx = find_cipher(sqlcipher_get_cipher(ctx));
  return cipher_descriptor[cipher_idx].max_key_length;
}

int sqlcipher_get_iv_sz(void *ctx) {
  int cipher_idx = find_cipher(sqlcipher_get_cipher(ctx));
  return cipher_descriptor[cipher_idx].block_length;
}

int sqlcipher_get_block_sz(void *ctx) {
  int cipher_idx = find_cipher(sqlcipher_get_cipher(ctx));
  return cipher_descriptor[cipher_idx].block_length;
}

int sqlcipher_get_hmac_sz(void *ctx) {
  int hash_idx = find_hash("sha1");
  return hash_descriptor[hash_idx].hashsize;
}

int sqlcipher_ctx_copy(void *target_ctx, void *source_ctx) {
  return 1;
}

int sqlcipher_ctx_cmp(void *c1, void *c2) {
  return 1;
}

int sqlcipher_ctx_init(void **ctx) {
  return SQLITE_OK;
}

int sqlcipher_ctx_free(void **ctx) {
  return SQLITE_OK;
}
#endif
