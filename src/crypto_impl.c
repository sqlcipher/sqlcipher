/* 
** SQLCipher
** crypto_impl.c developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** Copyright (c) 2011, ZETETIC LLC
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
/* BEGIN CRYPTO */
#ifdef SQLITE_HAS_CODEC

#include "sqliteInt.h"
#include "btreeInt.h"
#include "sqlcipher.h"
#include "crypto.h"
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) 
#include <sys/mman.h>
#elif defined(_WIN32)
# include <windows.h>
#endif
#endif

/* the default implementation of SQLCipher uses a cipher_ctx
   to keep track of read / write state separately. The following
   struct and associated functions are defined here */
typedef struct {
  int derive_key;
  int kdf_iter;
  int fast_kdf_iter;
  int key_sz;
  int iv_sz;
  int block_sz;
  int pass_sz;
  int reserve_sz;
  int hmac_sz;
  unsigned int flags;
  unsigned char *key;
  unsigned char *hmac_key;
  char *pass;
  sqlcipher_provider *provider;
  void *provider_ctx;
} cipher_ctx;

static unsigned int default_flags = DEFAULT_CIPHER_FLAGS;
static unsigned char hmac_salt_mask = HMAC_SALT_MASK;

static sqlcipher_provider *default_provider = NULL;

struct codec_ctx {
  int kdf_salt_sz;
  int page_sz;
  unsigned char *kdf_salt;
  unsigned char *hmac_kdf_salt;
  unsigned char *buffer;
  Btree *pBt;
  cipher_ctx *read_ctx;
  cipher_ctx *write_ctx;
};

int sqlcipher_register_provider(sqlcipher_provider *p) {
  if(default_provider != NULL) {
    sqlcipher_free(default_provider, sizeof(sqlcipher_provider));
  }
  default_provider = p;   
}

void sqlcipher_activate() {
  sqlcipher_provider *p;
  sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
  p = sqlcipher_malloc(sizeof(sqlcipher_provider));
  {
#if defined (SQLCIPHER_CRYPTO_CC)
  extern int sqlcipher_cc_setup(sqlcipher_provider *p);
  sqlcipher_cc_setup(p);
#elif SQLCIPHER_CRYPTO_LIBTOMCRYPT
  extern int sqlcipher_ltc_setup(sqlcipher_provider *p);
  sqlcipher_ltc_setup(p);
#elif SQLCIPHER_CRYPTO_OPENSSL
  extern int sqlcipher_openssl_setup(sqlcipher_provider *p);
  sqlcipher_openssl_setup(p);
#else
#error "NO DEFAULT SQLCIPHER CRYPTO PROVIDER DEFINED"
#endif
  }
  sqlcipher_register_provider(p);

  sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
}

void sqlcipher_deactivate() {
  sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
  if(default_provider != NULL) {
    sqlcipher_free(default_provider, sizeof(sqlcipher_provider));
    default_provider = NULL;
  }
  sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
}

/* constant time memset using volitile to avoid having the memset
   optimized out by the compiler. 
   Note: As suggested by Joachim Schipper (joachim.schipper@fox-it.com)
*/
void* sqlcipher_memset(void *v, unsigned char value, int len) {
  int i = 0;
  volatile unsigned char *a = v;

  if (v == NULL) return v;

  for(i = 0; i < len; i++) {
    a[i] = value;
  }

  return v;
}

/* constant time memory check tests every position of a memory segement
   matches a single value (i.e. the memory is all zeros)
   returns 0 if match, 1 of no match */
int sqlcipher_ismemset(const void *v, unsigned char value, int len) {
  const unsigned char *a = v;
  int i = 0, result = 0;

  for(i = 0; i < len; i++) {
    result |= a[i] ^ value;
  }

  return (result != 0);
}

/* constant time memory comparison routine. 
   returns 0 if match, 1 if no match */
int sqlcipher_memcmp(const void *v0, const void *v1, int len) {
  const unsigned char *a0 = v0, *a1 = v1;
  int i = 0, result = 0;

  for(i = 0; i < len; i++) {
    result |= a0[i] ^ a1[i];
  }
  
  return (result != 0);
}

/**
  * Free and wipe memory. Uses SQLites internal sqlite3_free so that memory
  * can be countend and memory leak detection works in the test suite. 
  * If ptr is not null memory will be freed. 
  * If sz is greater than zero, the memory will be overwritten with zero before it is freed
  * If sz is > 0, and not compiled with OMIT_MEMLOCK, system will attempt to unlock the
  * memory segment so it can be paged
  */
void sqlcipher_free(void *ptr, int sz) {
  if(ptr) {
    if(sz > 0) {
      sqlcipher_memset(ptr, 0, sz);
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) 
      munlock(ptr, sz);
#elif defined(_WIN32)
      VirtualUnlock(ptr, sz);
#endif
#endif
    }
    sqlite3_free(ptr);
  }
}

/**
  * allocate memory. Uses sqlite's internall malloc wrapper so memory can be 
  * reference counted and leak detection works. Unless compiled with OMIT_MEMLOCK
  * attempts to lock the memory pages so sensitive information won't be swapped
  */
void* sqlcipher_malloc(int sz) {
  void *ptr = sqlite3Malloc(sz);
  sqlcipher_memset(ptr, 0, sz);
#ifndef OMIT_MEMLOCK
  if(ptr) {
#if defined(__unix__) || defined(__APPLE__) 
    mlock(ptr, sz);
#elif defined(_WIN32)
    VirtualLock(ptr, sz);
#endif
  }
#endif
  return ptr;
}


/**
  * Initialize new cipher_ctx struct. This function will allocate memory
  * for the cipher context and for the key
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_init(cipher_ctx **iCtx) {
  int rc;
  cipher_ctx *ctx;
  *iCtx = (cipher_ctx *) sqlcipher_malloc(sizeof(cipher_ctx));
  ctx = *iCtx;
  if(ctx == NULL) return SQLITE_NOMEM;

  ctx->provider = (sqlcipher_provider *) sqlcipher_malloc(sizeof(sqlcipher_provider));
  if(ctx->provider == NULL) return SQLITE_NOMEM;
  memcpy(ctx->provider, default_provider, sizeof(sqlcipher_provider));

  if((rc = ctx->provider->ctx_init(&ctx->provider_ctx)) != SQLITE_OK) return rc;
  ctx->key = (unsigned char *) sqlcipher_malloc(CIPHER_MAX_KEY_SZ);
  ctx->hmac_key = (unsigned char *) sqlcipher_malloc(CIPHER_MAX_KEY_SZ);
  if(ctx->key == NULL) return SQLITE_NOMEM;
  if(ctx->hmac_key == NULL) return SQLITE_NOMEM;

  /* setup default flags */
  ctx->flags = default_flags;

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx
  */
static void sqlcipher_cipher_ctx_free(cipher_ctx **iCtx) {
  cipher_ctx *ctx = *iCtx;
  CODEC_TRACE(("cipher_ctx_free: entered iCtx=%p\n", iCtx));
  ctx->provider->ctx_free(&ctx->provider_ctx);
  sqlcipher_free(ctx->provider, sizeof(sqlcipher_provider)); 
  sqlcipher_free(ctx->key, ctx->key_sz);
  sqlcipher_free(ctx->hmac_key, ctx->key_sz);
  sqlcipher_free(ctx->pass, ctx->pass_sz);
  sqlcipher_free(ctx, sizeof(cipher_ctx)); 
}

/**
  * Compare one cipher_ctx to another.
  *
  * returns 0 if all the parameters (except the derived key data) are the same
  * returns 1 otherwise
  */
static int sqlcipher_cipher_ctx_cmp(cipher_ctx *c1, cipher_ctx *c2) {
  CODEC_TRACE(("sqlcipher_cipher_ctx_cmp: entered c1=%p c2=%p\n", c1, c2));

  if(
    c1->iv_sz == c2->iv_sz
    && c1->kdf_iter == c2->kdf_iter
    && c1->fast_kdf_iter == c2->fast_kdf_iter
    && c1->key_sz == c2->key_sz
    && c1->pass_sz == c2->pass_sz
    && c1->flags == c2->flags
    && c1->hmac_sz == c2->hmac_sz
    && c1->provider->ctx_cmp(c1->provider_ctx, c2->provider_ctx) 
    && (
      c1->pass == c2->pass
      || !sqlcipher_memcmp((const unsigned char*)c1->pass,
                           (const unsigned char*)c2->pass,
                           c1->pass_sz)
    ) 
  ) return 0;
  return 1;
}

/**
  * Copy one cipher_ctx to another. For instance, assuming that read_ctx is a 
  * fully initialized context, you could copy it to write_ctx and all yet data
  * and pass information across
  *
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_copy(cipher_ctx *target, cipher_ctx *source) {
  void *key = target->key; 
  void *hmac_key = target->hmac_key; 
  void *provider = target->provider;
  void *provider_ctx = target->provider_ctx;

  CODEC_TRACE(("sqlcipher_cipher_ctx_copy: entered target=%p, source=%p\n", target, source));
  sqlcipher_free(target->pass, target->pass_sz); 
  memcpy(target, source, sizeof(cipher_ctx));
  
  target->key = key; //restore pointer to previously allocated key data
  memcpy(target->key, source->key, CIPHER_MAX_KEY_SZ);

  target->hmac_key = hmac_key; //restore pointer to previously allocated hmac key data
  memcpy(target->hmac_key, source->hmac_key, CIPHER_MAX_KEY_SZ);

  target->provider = provider; // restore pointer to previouly allocated provider;
  memcpy(target->provider, source->provider, sizeof(sqlcipher_provider));

  target->provider_ctx = provider_ctx; // restore pointer to previouly allocated provider context;
  target->provider->ctx_copy(target->provider_ctx, source->provider_ctx);

  target->pass = sqlcipher_malloc(source->pass_sz);
  if(target->pass == NULL) return SQLITE_NOMEM;
  memcpy(target->pass, source->pass, source->pass_sz);

  return SQLITE_OK;
}


/**
  * Set the raw password / key data for a cipher context
  * 
  * returns SQLITE_OK if assignment was successfull
  * returns SQLITE_NOMEM if an error occured allocating memory
  * returns SQLITE_ERROR if the key couldn't be set because the pass was null or size was zero
  */
static int sqlcipher_cipher_ctx_set_pass(cipher_ctx *ctx, const void *zKey, int nKey) {
  sqlcipher_free(ctx->pass, ctx->pass_sz);
  ctx->pass_sz = nKey;
  if(zKey && nKey) {
    ctx->pass = sqlcipher_malloc(nKey);
    if(ctx->pass == NULL) return SQLITE_NOMEM;
    memcpy(ctx->pass, zKey, nKey);
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

int sqlcipher_codec_ctx_set_pass(codec_ctx *ctx, const void *zKey, int nKey, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  if((rc = sqlcipher_cipher_ctx_set_pass(c_ctx, zKey, nKey)) != SQLITE_OK) return rc; 
  c_ctx->derive_key = 1;

  if(for_ctx == 2)
    if((rc = sqlcipher_cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK) 
      return rc; 

  return SQLITE_OK;
} 

int sqlcipher_codec_ctx_set_cipher(codec_ctx *ctx, const char *cipher_name, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  c_ctx->provider->set_cipher(c_ctx->provider_ctx, cipher_name);

  c_ctx->key_sz = c_ctx->provider->get_key_sz(c_ctx->provider_ctx);
  c_ctx->iv_sz = c_ctx->provider->get_iv_sz(c_ctx->provider_ctx);
  c_ctx->block_sz = c_ctx->provider->get_block_sz(c_ctx->provider_ctx);
  c_ctx->hmac_sz = c_ctx->provider->get_hmac_sz(c_ctx->provider_ctx);
  c_ctx->derive_key = 1;

  if(for_ctx == 2)
    if((rc = sqlcipher_cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK)
      return rc; 

  return SQLITE_OK;
}

const char* sqlcipher_codec_ctx_get_cipher(codec_ctx *ctx, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  return c_ctx->provider->get_cipher(c_ctx->provider_ctx);
}

int sqlcipher_codec_ctx_set_kdf_iter(codec_ctx *ctx, int kdf_iter, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  c_ctx->kdf_iter = kdf_iter;
  c_ctx->derive_key = 1;

  if(for_ctx == 2)
    if((rc = sqlcipher_cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK)
      return rc; 

  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_kdf_iter(codec_ctx *ctx, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  return c_ctx->kdf_iter;
}

int sqlcipher_codec_ctx_set_fast_kdf_iter(codec_ctx *ctx, int fast_kdf_iter, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  c_ctx->fast_kdf_iter = fast_kdf_iter;
  c_ctx->derive_key = 1;

  if(for_ctx == 2)
    if((rc = sqlcipher_cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK)
      return rc; 

  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_fast_kdf_iter(codec_ctx *ctx, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  return c_ctx->fast_kdf_iter;
}

/* set the global default flag for HMAC */
void sqlcipher_set_default_use_hmac(int use) {
  if(use) default_flags |= CIPHER_FLAG_HMAC; 
  else default_flags &= ~CIPHER_FLAG_HMAC; 
}

int sqlcipher_get_default_use_hmac() {
  return (default_flags & CIPHER_FLAG_HMAC) != 0;
}

void sqlcipher_set_hmac_salt_mask(unsigned char mask) {
  hmac_salt_mask = mask;
}

unsigned char sqlcipher_get_hmac_salt_mask() {
  return hmac_salt_mask;
}

/* set the codec flag for whether this individual database should be using hmac */
int sqlcipher_codec_ctx_set_use_hmac(codec_ctx *ctx, int use) {
  int reserve = CIPHER_MAX_IV_SZ; /* base reserve size will be IV only */ 

  if(use) reserve += ctx->read_ctx->hmac_sz; /* if reserve will include hmac, update that size */

  /* calculate the amount of reserve needed in even increments of the cipher block size */

  reserve = ((reserve % ctx->read_ctx->block_sz) == 0) ? reserve :
               ((reserve / ctx->read_ctx->block_sz) + 1) * ctx->read_ctx->block_sz;  

  CODEC_TRACE(("sqlcipher_codec_ctx_set_use_hmac: use=%d block_sz=%d md_size=%d reserve=%d\n", 
                use, ctx->read_ctx->block_sz, ctx->read_ctx->hmac_sz, reserve)); 

  
  if(use) {
    sqlcipher_codec_ctx_set_flag(ctx, CIPHER_FLAG_HMAC);
  } else {
    sqlcipher_codec_ctx_unset_flag(ctx, CIPHER_FLAG_HMAC);
  } 
  
  ctx->write_ctx->reserve_sz = ctx->read_ctx->reserve_sz = reserve;

  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_use_hmac(codec_ctx *ctx, int for_ctx) {
  cipher_ctx * c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  return (c_ctx->flags & CIPHER_FLAG_HMAC) != 0;
}

int sqlcipher_codec_ctx_set_flag(codec_ctx *ctx, unsigned int flag) {
  ctx->write_ctx->flags |= flag;
  ctx->read_ctx->flags |= flag;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_unset_flag(codec_ctx *ctx, unsigned int flag) {
  ctx->write_ctx->flags &= ~flag;
  ctx->read_ctx->flags &= ~flag;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_flag(codec_ctx *ctx, unsigned int flag, int for_ctx) {
  cipher_ctx * c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  return (c_ctx->flags & flag) != 0;
}

void sqlcipher_codec_ctx_set_error(codec_ctx *ctx, int error) {
  CODEC_TRACE(("sqlcipher_codec_ctx_set_error: ctx=%p, error=%d\n", ctx, error));
  sqlite3pager_sqlite3PagerSetError(ctx->pBt->pBt->pPager, error);
  ctx->pBt->pBt->db->errCode = error;
}

int sqlcipher_codec_ctx_get_reservesize(codec_ctx *ctx) {
  return ctx->read_ctx->reserve_sz;
}

void* sqlcipher_codec_ctx_get_data(codec_ctx *ctx) {
  return ctx->buffer;
}

void* sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx) {
  return ctx->kdf_salt;
}

void sqlcipher_codec_get_pass(codec_ctx *ctx, void **zKey, int *nKey) {
  *zKey = ctx->read_ctx->pass;
  *nKey = ctx->read_ctx->pass_sz;
}

int sqlcipher_codec_ctx_set_pagesize(codec_ctx *ctx, int size) {
  /* attempt to free the existing page buffer */
  sqlcipher_free(ctx->buffer,ctx->page_sz);
  ctx->page_sz = size;

  /* pre-allocate a page buffer of PageSize bytes. This will
     be used as a persistent buffer for encryption and decryption 
     operations to avoid overhead of multiple memory allocations*/
  ctx->buffer = sqlcipher_malloc(size);
  if(ctx->buffer == NULL) return SQLITE_NOMEM;

  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_pagesize(codec_ctx *ctx) {
  return ctx->page_sz;
}

int sqlcipher_codec_ctx_init(codec_ctx **iCtx, Db *pDb, Pager *pPager, sqlite3_file *fd, const void *zKey, int nKey) {
  int rc;
  codec_ctx *ctx;
  *iCtx = sqlcipher_malloc(sizeof(codec_ctx));
  ctx = *iCtx;

  if(ctx == NULL) return SQLITE_NOMEM;

  ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */

  /* allocate space for salt data. Then read the first 16 bytes 
       directly off the database file. This is the salt for the
       key derivation function. If we get a short read allocate
       a new random salt value */
  ctx->kdf_salt_sz = FILE_HEADER_SZ;
  ctx->kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz);
  if(ctx->kdf_salt == NULL) return SQLITE_NOMEM;

  /* allocate space for separate hmac salt data. We want the
     HMAC derivation salt to be different than the encryption
     key derivation salt */
  ctx->hmac_kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz);
  if(ctx->hmac_kdf_salt == NULL) return SQLITE_NOMEM;


  /*
     Always overwrite page size and set to the default because the first page of the database
     in encrypted and thus sqlite can't effectively determine the pagesize. this causes an issue in 
     cases where bytes 16 & 17 of the page header are a power of 2 as reported by John Lehman
  */
  if((rc = sqlcipher_codec_ctx_set_pagesize(ctx, SQLITE_DEFAULT_PAGE_SIZE)) != SQLITE_OK) return rc;

  if((rc = sqlcipher_cipher_ctx_init(&ctx->read_ctx)) != SQLITE_OK) return rc; 
  if((rc = sqlcipher_cipher_ctx_init(&ctx->write_ctx)) != SQLITE_OK) return rc; 

  if(fd == NULL || sqlite3OsRead(fd, ctx->kdf_salt, FILE_HEADER_SZ, 0) != SQLITE_OK) {
    /* if unable to read the bytes, generate random salt */
    if(ctx->read_ctx->provider->random(ctx->read_ctx->provider_ctx, ctx->kdf_salt, FILE_HEADER_SZ) != SQLITE_OK) return SQLITE_ERROR;
  }

  if((rc = sqlcipher_codec_ctx_set_cipher(ctx, CIPHER, 0)) != SQLITE_OK) return rc;
  if((rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, PBKDF2_ITER, 0)) != SQLITE_OK) return rc;
  if((rc = sqlcipher_codec_ctx_set_fast_kdf_iter(ctx, FAST_PBKDF2_ITER, 0)) != SQLITE_OK) return rc;
  if((rc = sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, 0)) != SQLITE_OK) return rc;

  /* Note that use_hmac is a special case that requires recalculation of page size
     so we call set_use_hmac to perform setup */
  if((rc = sqlcipher_codec_ctx_set_use_hmac(ctx, default_flags & CIPHER_FLAG_HMAC)) != SQLITE_OK) return rc;

  if((rc = sqlcipher_cipher_ctx_copy(ctx->write_ctx, ctx->read_ctx)) != SQLITE_OK) return rc;

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx, including the allocated
  * read_ctx and write_ctx.
  */
void sqlcipher_codec_ctx_free(codec_ctx **iCtx) {
  codec_ctx *ctx = *iCtx;
  CODEC_TRACE(("codec_ctx_free: entered iCtx=%p\n", iCtx));
  sqlcipher_free(ctx->kdf_salt, ctx->kdf_salt_sz);
  sqlcipher_free(ctx->hmac_kdf_salt, ctx->kdf_salt_sz);
  sqlcipher_free(ctx->buffer, 0);
  sqlcipher_cipher_ctx_free(&ctx->read_ctx);
  sqlcipher_cipher_ctx_free(&ctx->write_ctx);
  sqlcipher_free(ctx, sizeof(codec_ctx)); 
}

/** convert a 32bit unsigned integer to little endian byte ordering */
static void sqlcipher_put4byte_le(unsigned char *p, u32 v) { 
  p[0] = (u8)v;
  p[1] = (u8)(v>>8);
  p[2] = (u8)(v>>16);
  p[3] = (u8)(v>>24);
}

static int sqlcipher_page_hmac(cipher_ctx *ctx, Pgno pgno, unsigned char *in, int in_sz, unsigned char *out) {
  unsigned char pgno_raw[sizeof(pgno)];
  /* we may convert page number to consistent representation before calculating MAC for
     compatibility across big-endian and little-endian platforms. 

     Note: The public release of sqlcipher 2.0.0 to 2.0.6 had a bug where the bytes of pgno 
     were used directly in the MAC. SQLCipher convert's to little endian by default to preserve
     backwards compatibility on the most popular platforms, but can optionally be configured
     to use either big endian or native byte ordering via pragma. */

  if(ctx->flags & CIPHER_FLAG_LE_PGNO) { /* compute hmac using little endian pgno*/
    sqlcipher_put4byte_le(pgno_raw, pgno);
  } else if(ctx->flags & CIPHER_FLAG_BE_PGNO) { /* compute hmac using big endian pgno */
    sqlite3Put4byte(pgno_raw, pgno); /* sqlite3Put4byte converts 32bit uint to big endian  */
  } else { /* use native byte ordering */
    memcpy(pgno_raw, &pgno, sizeof(pgno));
  }

  /* include the encrypted page data,  initialization vector, and page number in HMAC. This will 
     prevent both tampering with the ciphertext, manipulation of the IV, or resequencing otherwise
     valid pages out of order in a database */ 
  ctx->provider->hmac(
    ctx->provider_ctx, ctx->hmac_key,
    ctx->key_sz, in,
    in_sz, (unsigned char*) &pgno_raw,
    sizeof(pgno), out);
  return SQLITE_OK; 
}

/*
 * ctx - codec context
 * pgno - page number in database
 * size - size in bytes of input and output buffers
 * mode - 1 to encrypt, 0 to decrypt
 * in - pointer to input bytes
 * out - pouter to output bytes
 */
int sqlcipher_page_cipher(codec_ctx *ctx, int for_ctx, Pgno pgno, int mode, int page_sz, unsigned char *in, unsigned char *out) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  unsigned char *iv_in, *iv_out, *hmac_in, *hmac_out, *out_start;
  int tmp_csz, csz, size;

  /* calculate some required positions into various buffers */
  size = page_sz - c_ctx->reserve_sz; /* adjust size to useable size and memset reserve at end of page */
  iv_out = out + size;
  iv_in = in + size;

  /* hmac will be written immediately after the initialization vector. the remainder of the page reserve will contain
     random bytes. note, these pointers are only valid when using hmac */
  hmac_in = in + size + c_ctx->iv_sz; 
  hmac_out = out + size + c_ctx->iv_sz;
  out_start = out; /* note the original position of the output buffer pointer, as out will be rewritten during encryption */

  CODEC_TRACE(("codec_cipher:entered pgno=%d, mode=%d, size=%d\n", pgno, mode, size));
  CODEC_HEXDUMP("codec_cipher: input page data", in, page_sz);

  /* the key size should never be zero. If it is, error out. */
  if(c_ctx->key_sz == 0) {
    CODEC_TRACE(("codec_cipher: error possible context corruption, key_sz is zero for pgno=%d\n", pgno));
    sqlcipher_memset(out, 0, page_sz); 
    return SQLITE_ERROR;
  } 

  if(mode == CIPHER_ENCRYPT) {
    /* start at front of the reserve block, write random data to the end */
    if(c_ctx->provider->random(c_ctx->provider_ctx, iv_out, c_ctx->reserve_sz) != SQLITE_OK) return SQLITE_ERROR; 
  } else { /* CIPHER_DECRYPT */
    memcpy(iv_out, iv_in, c_ctx->iv_sz); /* copy the iv from the input to output buffer */
  } 

  if((c_ctx->flags & CIPHER_FLAG_HMAC) && (mode == CIPHER_DECRYPT)) {
    if(sqlcipher_page_hmac(c_ctx, pgno, in, size + c_ctx->iv_sz, hmac_out) != SQLITE_OK) {
      sqlcipher_memset(out, 0, page_sz); 
      CODEC_TRACE(("codec_cipher: hmac operations failed for pgno=%d\n", pgno));
      return SQLITE_ERROR;
    }

    CODEC_TRACE(("codec_cipher: comparing hmac on in=%p out=%p hmac_sz=%d\n", hmac_in, hmac_out, c_ctx->hmac_sz));
    if(sqlcipher_memcmp(hmac_in, hmac_out, c_ctx->hmac_sz) != 0) { /* the hmac check failed */ 
      if(sqlcipher_ismemset(in, 0, page_sz) == 0) {
        /* first check if the entire contents of the page is zeros. If so, this page 
           resulted from a short read (i.e. sqlite attempted to pull a page after the end of the file. these 
           short read failures must be ignored for autovaccum mode to work so wipe the output buffer 
           and return SQLITE_OK to skip the decryption step. */
        CODEC_TRACE(("codec_cipher: zeroed page (short read) for pgno %d, encryption but returning SQLITE_OK\n", pgno));
        sqlcipher_memset(out, 0, page_sz); 
  	return SQLITE_OK;
      } else {
	/* if the page memory is not all zeros, it means the there was data and a hmac on the page. 
           since the check failed, the page was either tampered with or corrupted. wipe the output buffer,
           and return SQLITE_ERROR to the caller */
      	CODEC_TRACE(("codec_cipher: hmac check failed for pgno=%d returning SQLITE_ERROR\n", pgno));
        sqlcipher_memset(out, 0, page_sz); 
      	return SQLITE_ERROR;
      }
    }
  } 
  
  c_ctx->provider->cipher(c_ctx->provider_ctx, mode, c_ctx->key, c_ctx->key_sz, iv_out, in, size, out);

  if((c_ctx->flags & CIPHER_FLAG_HMAC) && (mode == CIPHER_ENCRYPT)) {
    sqlcipher_page_hmac(c_ctx, pgno, out_start, size + c_ctx->iv_sz, hmac_out); 
  }

  CODEC_HEXDUMP("codec_cipher: output page data", out_start, page_sz);

  return SQLITE_OK;
}

/**
  * Derive an encryption key for a cipher contex key based on the raw password.
  *
  * If the raw key data is formated as x'hex' and there are exactly enough hex chars to fill
  * the key space (i.e 64 hex chars for a 256 bit key) then the key data will be used directly. 
  * 
  * Otherwise, a key data will be derived using PBKDF2
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_ERROR if the key could't be derived (for instance if pass is NULL or pass_sz is 0)
  */
static int sqlcipher_cipher_ctx_key_derive(codec_ctx *ctx, cipher_ctx *c_ctx) {
  CODEC_TRACE(("codec_key_derive: entered c_ctx->pass=%s, c_ctx->pass_sz=%d \
                ctx->kdf_salt=%p ctx->kdf_salt_sz=%d c_ctx->kdf_iter=%d \
                ctx->hmac_kdf_salt=%p, c_ctx->fast_kdf_iter=%d c_ctx->key_sz=%d\n", 
                c_ctx->pass, c_ctx->pass_sz, ctx->kdf_salt, ctx->kdf_salt_sz, c_ctx->kdf_iter, 
                ctx->hmac_kdf_salt, c_ctx->fast_kdf_iter, c_ctx->key_sz)); 
                

  if(c_ctx->pass && c_ctx->pass_sz) { // if pass is not null
    if (c_ctx->pass_sz == ((c_ctx->key_sz*2)+3) && sqlite3StrNICmp(c_ctx->pass ,"x'", 2) == 0) { 
      int n = c_ctx->pass_sz - 3; /* adjust for leading x' and tailing ' */
      const char *z = c_ctx->pass + 2; /* adjust lead offset of x' */
      CODEC_TRACE(("codec_key_derive: using raw key from hex\n")); 
      cipher_hex2bin(z, n, c_ctx->key);
    } else { 
      CODEC_TRACE(("codec_key_derive: deriving key using full PBKDF2 with %d iterations\n", c_ctx->kdf_iter)); 
      c_ctx->provider->kdf(c_ctx->provider_ctx, c_ctx->pass, c_ctx->pass_sz, 
                    ctx->kdf_salt, ctx->kdf_salt_sz, c_ctx->kdf_iter,
                    c_ctx->key_sz, c_ctx->key);
                              
    }

    /* if this context is setup to use hmac checks, generate a seperate and different 
       key for HMAC. In this case, we use the output of the previous KDF as the input to 
       this KDF run. This ensures a distinct but predictable HMAC key. */
    if(c_ctx->flags & CIPHER_FLAG_HMAC) {
      int i;

      /* start by copying the kdf key into the hmac salt slot
         then XOR it with the fixed hmac salt defined at compile time
         this ensures that the salt passed in to derive the hmac key, while 
         easy to derive and publically known, is not the same as the salt used 
         to generate the encryption key */ 
      memcpy(ctx->hmac_kdf_salt, ctx->kdf_salt, ctx->kdf_salt_sz);
      for(i = 0; i < ctx->kdf_salt_sz; i++) {
        ctx->hmac_kdf_salt[i] ^= hmac_salt_mask;
      } 

      CODEC_TRACE(("codec_key_derive: deriving hmac key from encryption key using PBKDF2 with %d iterations\n", 
        c_ctx->fast_kdf_iter)); 

      
      c_ctx->provider->kdf(c_ctx->provider_ctx, (const char*)c_ctx->key, c_ctx->key_sz, 
                    ctx->hmac_kdf_salt, ctx->kdf_salt_sz, c_ctx->fast_kdf_iter,
                    c_ctx->key_sz, c_ctx->hmac_key); 
    }

    c_ctx->derive_key = 0;
    return SQLITE_OK;
  };
  return SQLITE_ERROR;
}

int sqlcipher_codec_key_derive(codec_ctx *ctx) {
  /* derive key on first use if necessary */
  if(ctx->read_ctx->derive_key) {
    if(sqlcipher_cipher_ctx_key_derive(ctx, ctx->read_ctx) != SQLITE_OK) return SQLITE_ERROR;
  }

  if(ctx->write_ctx->derive_key) {
    if(sqlcipher_cipher_ctx_cmp(ctx->write_ctx, ctx->read_ctx) == 0) {
      // the relevant parameters are the same, just copy read key
      if(sqlcipher_cipher_ctx_copy(ctx->write_ctx, ctx->read_ctx) != SQLITE_OK) return SQLITE_ERROR;
    } else {
      if(sqlcipher_cipher_ctx_key_derive(ctx, ctx->write_ctx) != SQLITE_OK) return SQLITE_ERROR;
    }
  }
  return SQLITE_OK; 
}

int sqlcipher_codec_key_copy(codec_ctx *ctx, int source) {
  if(source == CIPHER_READ_CTX) { 
      return sqlcipher_cipher_ctx_copy(ctx->write_ctx, ctx->read_ctx); 
  } else {
      return sqlcipher_cipher_ctx_copy(ctx->read_ctx, ctx->write_ctx); 
  }
}

const char* sqlcipher_codec_get_cipher_provider(codec_ctx *ctx) {
  return ctx->read_ctx->provider->get_provider_name(ctx->read_ctx);
}

#endif
