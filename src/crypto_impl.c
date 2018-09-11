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

#include "sqlcipher.h"
#include "crypto.h"
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) || defined(_AIX)
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/mman.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#endif

static volatile unsigned int default_flags = DEFAULT_CIPHER_FLAGS;
static volatile unsigned char hmac_salt_mask = HMAC_SALT_MASK;
static volatile int default_kdf_iter = PBKDF2_ITER;
static volatile int default_page_size = 4096;
static volatile int default_plaintext_header_sz = 0;
static volatile int default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
static volatile int default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
static volatile int mem_security_on = 1;
static volatile int mem_security_activated = 0;
static volatile unsigned int sqlcipher_activate_count = 0;
static volatile sqlite3_mem_methods default_mem_methods;
static sqlite3_mutex* sqlcipher_provider_mutex = NULL;
static sqlcipher_provider *default_provider = NULL;

/* the default implementation of SQLCipher uses a cipher_ctx
   to keep track of read / write state separately. The following
   struct and associated functions are defined here */
typedef struct {
  int derive_key; 
  int pass_sz;
  unsigned char *key;
  unsigned char *hmac_key;
  unsigned char *pass;
  char *keyspec;
} cipher_ctx;


struct codec_ctx {
  int store_pass; 
  int kdf_iter; 
  int fast_kdf_iter; 
  int kdf_salt_sz;
  int key_sz; 
  int iv_sz;
  int block_sz;
  int page_sz;
  int keyspec_sz; 
  int reserve_sz;
  int hmac_sz;
  int plaintext_header_sz;
  int hmac_algorithm;
  int kdf_algorithm;
  unsigned int skip_read_hmac;
  unsigned int need_kdf_salt;
  unsigned int flags;
  unsigned char *kdf_salt;
  unsigned char *hmac_kdf_salt;
  unsigned char *buffer;
  Btree *pBt;
  cipher_ctx *read_ctx;
  cipher_ctx *write_ctx;
  sqlcipher_provider *provider;
  void *provider_ctx;
};

static int sqlcipher_mem_init(void *pAppData) {
  return default_mem_methods.xInit(pAppData);
}
static void sqlcipher_mem_shutdown(void *pAppData) {
  default_mem_methods.xShutdown(pAppData);
}
static void *sqlcipher_mem_malloc(int n) {
  void *ptr = default_mem_methods.xMalloc(n);
  if(mem_security_on) {
    CODEC_TRACE("sqlcipher_mem_malloc: calling sqlcipher_mlock(%p,%d)\n", ptr, sz);
    sqlcipher_mlock(ptr, n); 
    if(!mem_security_activated) mem_security_activated = 1;
  }
  return ptr;
}
static int sqlcipher_mem_size(void *p) {
  return default_mem_methods.xSize(p);
}
static void sqlcipher_mem_free(void *p) {
  int sz;
  if(mem_security_on) {
    sz = sqlcipher_mem_size(p);
    CODEC_TRACE("sqlcipher_mem_free: calling sqlcipher_memset(%p,0,%d) and sqlcipher_munlock(%p, %d) \n", p, sz, p, sz);
    sqlcipher_memset(p, 0, sz);
    sqlcipher_munlock(p, sz);
    if(!mem_security_activated) mem_security_activated = 1;
  }
  default_mem_methods.xFree(p);
}
static void *sqlcipher_mem_realloc(void *p, int n) {
  return default_mem_methods.xRealloc(p, n);
}
static int sqlcipher_mem_roundup(int n) {
  return default_mem_methods.xRoundup(n);
}

static sqlite3_mem_methods sqlcipher_mem_methods = {
  sqlcipher_mem_malloc,
  sqlcipher_mem_free,
  sqlcipher_mem_realloc,
  sqlcipher_mem_size,
  sqlcipher_mem_roundup,
  sqlcipher_mem_init,
  sqlcipher_mem_shutdown,
  0
};

void sqlcipher_init_memmethods() {
  sqlite3_config(SQLITE_CONFIG_GETMALLOC, &default_mem_methods);
  sqlite3_config(SQLITE_CONFIG_MALLOC, &sqlcipher_mem_methods);
}

int sqlcipher_register_provider(sqlcipher_provider *p) {
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: entering sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
  sqlite3_mutex_enter(sqlcipher_provider_mutex);
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: entered sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);

  if(default_provider != NULL && default_provider != p) {
    /* only free the current registerd provider if it has been initialized
       and it isn't a pointer to the same provider passed to the function
       (i.e. protect against a caller calling register twice for the same provider) */
    sqlcipher_free(default_provider, sizeof(sqlcipher_provider));
  }
  default_provider = p;   
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: leaving sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
  sqlite3_mutex_leave(sqlcipher_provider_mutex);
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: left sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);

  return SQLITE_OK;
}

/* return a pointer to the currently registered provider. This will
   allow an application to fetch the current registered provider and
   make minor changes to it */
sqlcipher_provider* sqlcipher_get_provider() {
  return default_provider;
}

void sqlcipher_activate() {
  CODEC_TRACE_MUTEX("sqlcipher_activate: entering static master mutex\n");
  sqlite3_mutex_enter(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_activate: entered static master mutex\n");

  if(sqlcipher_provider_mutex == NULL) {
    /* allocate a new mutex to guard access to the provider */
    CODEC_TRACE_MUTEX("sqlcipher_activate: allocating sqlcipher provider mutex\n");
    sqlcipher_provider_mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
    CODEC_TRACE_MUTEX("sqlcipher_activate: allocated sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
  }

  /* check to see if there is a provider registered at this point
     if there no provider registered at this point, register the 
     default provider */
  if(sqlcipher_get_provider() == NULL) {
    sqlcipher_provider *p = sqlcipher_malloc(sizeof(sqlcipher_provider)); 
#if defined (SQLCIPHER_CRYPTO_CC)
    extern int sqlcipher_cc_setup(sqlcipher_provider *p);
    sqlcipher_cc_setup(p);
#elif defined (SQLCIPHER_CRYPTO_LIBTOMCRYPT)
    extern int sqlcipher_ltc_setup(sqlcipher_provider *p);
    sqlcipher_ltc_setup(p);
#elif defined (SQLCIPHER_CRYPTO_OPENSSL)
    extern int sqlcipher_openssl_setup(sqlcipher_provider *p);
    sqlcipher_openssl_setup(p);
#else
#error "NO DEFAULT SQLCIPHER CRYPTO PROVIDER DEFINED"
#endif
    CODEC_TRACE("sqlcipher_activate: calling sqlcipher_register_provider(%p)\n", p);
    sqlcipher_register_provider(p);
    CODEC_TRACE("sqlcipher_activate: called sqlcipher_register_provider(%p)\n",p);
  }

  sqlcipher_activate_count++; /* increment activation count */

  CODEC_TRACE_MUTEX("sqlcipher_activate: leaving static master mutex\n");
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_activate: left static master mutex\n");
}

void sqlcipher_deactivate() {
  CODEC_TRACE_MUTEX("sqlcipher_deactivate: entering static master mutex\n");
  sqlite3_mutex_enter(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_deactivate: entered static master mutex\n");

  sqlcipher_activate_count--;
  /* if no connections are using sqlcipher, cleanup globals */
  if(sqlcipher_activate_count < 1) {
    int rc;
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: entering sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
    sqlite3_mutex_enter(sqlcipher_provider_mutex);
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: entered sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);

    if(default_provider != NULL) {
      sqlcipher_free(default_provider, sizeof(sqlcipher_provider));
      default_provider = NULL;
    }

    CODEC_TRACE_MUTEX("sqlcipher_deactivate: leaving sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
    sqlite3_mutex_leave(sqlcipher_provider_mutex);
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: left sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
    
    /* last connection closed, free provider mutex*/
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: freeing sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
    sqlite3_mutex_free(sqlcipher_provider_mutex); 
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: freed sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);

    sqlcipher_provider_mutex = NULL;

    sqlcipher_activate_count = 0; /* reset activation count */
  }

  CODEC_TRACE_MUTEX("sqlcipher_deactivate: leaving static master mutex\n");
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_deactivate: left static master mutex\n");
}

/* constant time memset using volitile to avoid having the memset
   optimized out by the compiler. 
   Note: As suggested by Joachim Schipper (joachim.schipper@fox-it.com)
*/
void* sqlcipher_memset(void *v, unsigned char value, int len) {
  int i = 0;
  volatile unsigned char *a = v;

  if (v == NULL) return v;

  CODEC_TRACE("sqlcipher_memset: setting %p[0-%d]=%d)\n", a, len, value);
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

void sqlcipher_mlock(void *ptr, int sz) {
#ifndef OMIT_MEMLOCK
  int rc;
#if defined(__unix__) || defined(__APPLE__) 
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  unsigned long offset = (unsigned long) ptr % pagesize;

  if(ptr == NULL || sz == 0) return;

  CODEC_TRACE("sqlcipher_mem_lock: calling mlock(%p,%lu); _SC_PAGESIZE=%lu\n", ptr - offset, sz + offset, pagesize);
  rc = mlock(ptr - offset, sz + offset);
  if(rc!=0) {
    CODEC_TRACE("sqlcipher_mem_lock: mlock(%p,%lu) returned %d errno=%d\n", ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_APP))
  CODEC_TRACE("sqlcipher_mem_lock: calling VirtualLock(%p,%d)\n", ptr, sz);
  rc = VirtualLock(ptr, sz);
  if(rc==0) {
    CODEC_TRACE("sqlcipher_mem_lock: VirtualLock(%p,%d) returned %d LastError=%d\n", ptr, sz, rc, GetLastError());
  }
#endif
#endif
#endif
}

void sqlcipher_munlock(void *ptr, int sz) {
#ifndef OMIT_MEMLOCK
  int rc;
#if defined(__unix__) || defined(__APPLE__) 
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  unsigned long offset = (unsigned long) ptr % pagesize;

  if(ptr == NULL || sz == 0) return;

  CODEC_TRACE("sqlcipher_mem_unlock: calling munlock(%p,%lu)\n", ptr - offset, sz + offset);
  rc = munlock(ptr - offset, sz + offset);
  if(rc!=0) {
    CODEC_TRACE("sqlcipher_mem_unlock: munlock(%p,%lu) returned %d errno=%d\n", ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_APP))
  CODEC_TRACE("sqlcipher_mem_lock: calling VirtualUnlock(%p,%d)\n", ptr, sz);
  rc = VirtualUnlock(ptr, sz);
  if(!rc) {
    CODEC_TRACE("sqlcipher_mem_unlock: VirtualUnlock(%p,%d) returned %d LastError=%d\n", ptr, sz, rc, GetLastError());
  }
#endif
#endif
#endif
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
  CODEC_TRACE("sqlcipher_free: calling sqlcipher_memset(%p,0,%d)\n", ptr, sz);
  sqlcipher_memset(ptr, 0, sz);
  sqlcipher_munlock(ptr, sz);
  sqlite3_free(ptr);
}

/**
  * allocate memory. Uses sqlite's internall malloc wrapper so memory can be 
  * reference counted and leak detection works. Unless compiled with OMIT_MEMLOCK
  * attempts to lock the memory pages so sensitive information won't be swapped
  */
void* sqlcipher_malloc(int sz) {
  void *ptr;
  CODEC_TRACE("sqlcipher_malloc: calling sqlite3Malloc(%d)\n", sz);
  ptr = sqlite3Malloc(sz);
  CODEC_TRACE("sqlcipher_malloc: calling sqlcipher_memset(%p,0,%d)\n", ptr, sz);
  sqlcipher_memset(ptr, 0, sz);
  sqlcipher_mlock(ptr, sz);
  return ptr;
}

/**
  * Initialize new cipher_ctx struct. This function will allocate memory
  * for the cipher context and for the key
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_init(codec_ctx *ctx, cipher_ctx **iCtx) {
  int rc;
  cipher_ctx *c_ctx;
  CODEC_TRACE("sqlcipher_cipher_ctx_init: allocating context\n");
  *iCtx = (cipher_ctx *) sqlcipher_malloc(sizeof(cipher_ctx));
  c_ctx = *iCtx;
  if(c_ctx == NULL) return SQLITE_NOMEM;

  CODEC_TRACE("sqlcipher_cipher_ctx_init: allocating key\n");
  c_ctx->key = (unsigned char *) sqlcipher_malloc(ctx->key_sz);

  CODEC_TRACE("sqlcipher_cipher_ctx_init: allocating hmac_key\n");
  c_ctx->hmac_key = (unsigned char *) sqlcipher_malloc(ctx->key_sz);

  if(c_ctx->key == NULL) return SQLITE_NOMEM;
  if(c_ctx->hmac_key == NULL) return SQLITE_NOMEM;

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx
  */
static void sqlcipher_cipher_ctx_free(codec_ctx* ctx, cipher_ctx **iCtx) {
  cipher_ctx *c_ctx = *iCtx;
  CODEC_TRACE("cipher_ctx_free: entered iCtx=%p\n", iCtx);
  sqlcipher_free(c_ctx->key, ctx->key_sz);
  sqlcipher_free(c_ctx->hmac_key, ctx->key_sz);
  sqlcipher_free(c_ctx->pass, c_ctx->pass_sz);
  sqlcipher_free(c_ctx->keyspec, ctx->keyspec_sz);
  sqlcipher_free(c_ctx, sizeof(cipher_ctx)); 
}

static int sqlcipher_codec_ctx_reserve_setup(codec_ctx *ctx) {
  int base_reserve = CIPHER_MAX_IV_SZ; /* base reserve size will be IV only */ 
  int reserve = base_reserve;

  ctx->hmac_sz = ctx->provider->get_hmac_sz(ctx->provider_ctx, ctx->hmac_algorithm); 

  if(sqlcipher_codec_ctx_get_use_hmac(ctx))
    reserve += ctx->hmac_sz; /* if reserve will include hmac, update that size */

  /* calculate the amount of reserve needed in even increments of the cipher block size */
  reserve = ((reserve % ctx->block_sz) == 0) ? reserve :
               ((reserve / ctx->block_sz) + 1) * ctx->block_sz;  

  CODEC_TRACE("sqlcipher_codec_ctx_reserve_setup: base_reserve=%d block_sz=%d md_size=%d reserve=%d\n", 
                base_reserve, ctx->block_sz, ctx->hmac_sz, reserve); 

  ctx->reserve_sz = reserve;

  return SQLITE_OK;
}

/**
  * Compare one cipher_ctx to another.
  *
  * returns 0 if all the parameters (except the derived key data) are the same
  * returns 1 otherwise
  */
static int sqlcipher_cipher_ctx_cmp(cipher_ctx *c1, cipher_ctx *c2) {
  int are_equal = (
    c1->pass_sz == c2->pass_sz
    && (
      c1->pass == c2->pass
      || !sqlcipher_memcmp((const unsigned char*)c1->pass,
                           (const unsigned char*)c2->pass,
                           c1->pass_sz)
    ));

  CODEC_TRACE("sqlcipher_cipher_ctx_cmp: entered \
                  c1=%p c2=%p \
                  c1->pass_sz=%d c2->pass_sz=%d \
                  c1->pass=%p c2->pass=%p \
                  c1->pass=%s c2->pass=%s \
                  sqlcipher_memcmp=%d \
                  are_equal=%d \
                   \n", 
                  c1, c2,
                  c1->pass_sz, c2->pass_sz,
                  c1->pass, c2->pass,
                  c1->pass, c2->pass,
                  (c1->pass == NULL || c2->pass == NULL) 
                    ? -1 : sqlcipher_memcmp(
                      (const unsigned char*)c1->pass,
                      (const unsigned char*)c2->pass,
                      c1->pass_sz),
                  are_equal
                  );

  return !are_equal; /* return 0 if they are the same, 1 otherwise */
}

/**
  * Copy one cipher_ctx to another. For instance, assuming that read_ctx is a 
  * fully initialized context, you could copy it to write_ctx and all yet data
  * and pass information across
  *
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_copy(codec_ctx *ctx, cipher_ctx *target, cipher_ctx *source) {
  void *key = target->key; 
  void *hmac_key = target->hmac_key; 

  CODEC_TRACE("sqlcipher_cipher_ctx_copy: entered target=%p, source=%p\n", target, source);
  sqlcipher_free(target->pass, target->pass_sz); 
  sqlcipher_free(target->keyspec, ctx->keyspec_sz); 
  memcpy(target, source, sizeof(cipher_ctx));

  target->key = key; //restore pointer to previously allocated key data
  memcpy(target->key, source->key, ctx->key_sz);

  target->hmac_key = hmac_key; //restore pointer to previously allocated hmac key data
  memcpy(target->hmac_key, source->hmac_key, ctx->key_sz);

  if(source->pass && source->pass_sz) {
    target->pass = sqlcipher_malloc(source->pass_sz);
    if(target->pass == NULL) return SQLITE_NOMEM;
    memcpy(target->pass, source->pass, source->pass_sz);
  }
  if(source->keyspec) {
    target->keyspec = sqlcipher_malloc(ctx->keyspec_sz);
    if(target->keyspec == NULL) return SQLITE_NOMEM;
    memcpy(target->keyspec, source->keyspec, ctx->keyspec_sz);
  }
  return SQLITE_OK;
}

/**
  * Set the keyspec for the cipher_ctx
  * 
  * returns SQLITE_OK if assignment was successfull
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_set_keyspec(codec_ctx *ctx, cipher_ctx *c_ctx, const unsigned char *key) {
  /* free, zero existing pointers and size */
  sqlcipher_free(c_ctx->keyspec, ctx->keyspec_sz);
  c_ctx->keyspec = NULL;

  c_ctx->keyspec = sqlcipher_malloc(ctx->keyspec_sz);
  if(c_ctx->keyspec == NULL) return SQLITE_NOMEM;

  c_ctx->keyspec[0] = 'x';
  c_ctx->keyspec[1] = '\'';
  cipher_bin2hex(key, ctx->key_sz, c_ctx->keyspec + 2);
  cipher_bin2hex(ctx->kdf_salt, ctx->kdf_salt_sz, c_ctx->keyspec + (ctx->key_sz * 2) + 2);
  c_ctx->keyspec[ctx->keyspec_sz - 1] = '\'';
  return SQLITE_OK;
}

int sqlcipher_codec_get_store_pass(codec_ctx *ctx) {
  return ctx->store_pass;
}

void sqlcipher_codec_set_store_pass(codec_ctx *ctx, int value) {
  ctx->store_pass = value;
}

void sqlcipher_codec_get_pass(codec_ctx *ctx, void **zKey, int *nKey) {
  *zKey = ctx->read_ctx->pass;
  *nKey = ctx->read_ctx->pass_sz;
}

static void sqlcipher_set_derive_key(codec_ctx *ctx, int derive) {
  if(ctx->read_ctx != NULL) ctx->read_ctx->derive_key = 1;
  if(ctx->write_ctx != NULL) ctx->write_ctx->derive_key = 1;
}

/**
  * Set the passphrase for the cipher_ctx
  * 
  * returns SQLITE_OK if assignment was successfull
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_set_pass(cipher_ctx *ctx, const void *zKey, int nKey) {
  /* free, zero existing pointers and size */
  sqlcipher_free(ctx->pass, ctx->pass_sz);
  ctx->pass = NULL;
  ctx->pass_sz = 0;

  if(zKey && nKey) { /* if new password is provided, copy it */
    ctx->pass_sz = nKey;
    ctx->pass = sqlcipher_malloc(nKey);
    if(ctx->pass == NULL) return SQLITE_NOMEM;
    memcpy(ctx->pass, zKey, nKey);
  } 
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_set_pass(codec_ctx *ctx, const void *zKey, int nKey, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  if((rc = sqlcipher_cipher_ctx_set_pass(c_ctx, zKey, nKey)) != SQLITE_OK) return rc; 
  c_ctx->derive_key = 1;

  if(for_ctx == 2)
    if((rc = sqlcipher_cipher_ctx_copy(ctx, for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK) 
      return rc; 

  return SQLITE_OK;
} 

int sqlcipher_codec_ctx_set_cipher(codec_ctx *ctx, const char *cipher_name) {
  int rc;

  rc = ctx->provider->set_cipher(ctx->provider_ctx, cipher_name);
  if(rc != SQLITE_OK){
    sqlcipher_codec_ctx_set_error(ctx, rc);
    return rc;
  }
  ctx->key_sz = ctx->provider->get_key_sz(ctx->provider_ctx);
  ctx->iv_sz = ctx->provider->get_iv_sz(ctx->provider_ctx);
  ctx->block_sz = ctx->provider->get_block_sz(ctx->provider_ctx);

  sqlcipher_set_derive_key(ctx, 1);

  sqlcipher_codec_ctx_reserve_setup(ctx);
  return SQLITE_OK;
}

const char* sqlcipher_codec_ctx_get_cipher(codec_ctx *ctx) {
  return ctx->provider->get_cipher(ctx->provider_ctx);
}

/* set the global default KDF iteration */
void sqlcipher_set_default_kdf_iter(int iter) {
  default_kdf_iter = iter; 
}

int sqlcipher_get_default_kdf_iter() {
  return default_kdf_iter;
}

int sqlcipher_codec_ctx_set_kdf_iter(codec_ctx *ctx, int kdf_iter) {
  ctx->kdf_iter = kdf_iter;
  sqlcipher_set_derive_key(ctx, 1);
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_kdf_iter(codec_ctx *ctx) {
  return ctx->kdf_iter;
}

int sqlcipher_codec_ctx_set_fast_kdf_iter(codec_ctx *ctx, int fast_kdf_iter) {
  ctx->fast_kdf_iter = fast_kdf_iter;
  sqlcipher_set_derive_key(ctx, 1);
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_fast_kdf_iter(codec_ctx *ctx) {
  return ctx->fast_kdf_iter;
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
  if(use) {
    sqlcipher_codec_ctx_set_flag(ctx, CIPHER_FLAG_HMAC);
  } else {
    sqlcipher_codec_ctx_unset_flag(ctx, CIPHER_FLAG_HMAC);
  } 

  return sqlcipher_codec_ctx_reserve_setup(ctx);
}

int sqlcipher_codec_ctx_get_use_hmac(codec_ctx *ctx) {
  return (ctx->flags & CIPHER_FLAG_HMAC) != 0;
}

/* the length of plaintext header size must be:
 * 1. greater than or equal to zero
 * 2. a multiple of the cipher block size
 * 3. less than the usable size of the first database page
 */
int sqlcipher_set_default_plaintext_header_size(int size) {
  default_plaintext_header_sz = size;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_set_plaintext_header_size(codec_ctx *ctx, int size) {
  if(size >= 0 && (size % ctx->block_sz) == 0 && size < (ctx->page_sz - ctx->reserve_sz)) {
    ctx->plaintext_header_sz = size;
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
} 

int sqlcipher_get_default_plaintext_header_size() {
  return default_plaintext_header_sz;
}

int sqlcipher_codec_ctx_get_plaintext_header_size(codec_ctx *ctx) {
  return ctx->plaintext_header_sz;
}

/* manipulate HMAC algorithm */
int sqlcipher_set_default_hmac_algorithm(int algorithm) {
  default_hmac_algorithm = algorithm;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_set_hmac_algorithm(codec_ctx *ctx, int algorithm) {
  ctx->hmac_algorithm = algorithm;
  return sqlcipher_codec_ctx_reserve_setup(ctx);
} 

int sqlcipher_get_default_hmac_algorithm() {
  return default_hmac_algorithm;
}

int sqlcipher_codec_ctx_get_hmac_algorithm(codec_ctx *ctx) {
  return ctx->hmac_algorithm;
}

/* manipulate KDF algorithm */
int sqlcipher_set_default_kdf_algorithm(int algorithm) {
  default_kdf_algorithm = algorithm;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_set_kdf_algorithm(codec_ctx *ctx, int algorithm) {
  ctx->kdf_algorithm = algorithm;
  return SQLITE_OK;
} 

int sqlcipher_get_default_kdf_algorithm() {
  return default_kdf_algorithm;
}

int sqlcipher_codec_ctx_get_kdf_algorithm(codec_ctx *ctx) {
  return ctx->kdf_algorithm;
}

int sqlcipher_codec_ctx_set_flag(codec_ctx *ctx, unsigned int flag) {
  ctx->flags |= flag;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_unset_flag(codec_ctx *ctx, unsigned int flag) {
  ctx->flags &= ~flag;
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_get_flag(codec_ctx *ctx, unsigned int flag) {
  return (ctx->flags & flag) != 0;
}

void sqlcipher_codec_ctx_set_error(codec_ctx *ctx, int error) {
  CODEC_TRACE("sqlcipher_codec_ctx_set_error: ctx=%p, error=%d\n", ctx, error);
  sqlite3pager_sqlite3PagerSetError(ctx->pBt->pBt->pPager, error);
  ctx->pBt->pBt->db->errCode = error;
}

int sqlcipher_codec_ctx_get_reservesize(codec_ctx *ctx) {
  return ctx->reserve_sz;
}

void* sqlcipher_codec_ctx_get_data(codec_ctx *ctx) {
  return ctx->buffer;
}

int sqlcipher_codec_ctx_set_kdf_salt(codec_ctx *ctx, unsigned char *salt, int size) {
  if(size >= ctx->kdf_salt_sz) {
    memcpy(ctx->kdf_salt, salt, ctx->kdf_salt_sz);
    ctx->need_kdf_salt = 0;
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

void* sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx) {
  return ctx->kdf_salt;
}

void sqlcipher_codec_get_keyspec(codec_ctx *ctx, void **zKey, int *nKey) {
  *zKey = ctx->read_ctx->keyspec;
  *nKey = ctx->keyspec_sz;
}

int sqlcipher_codec_ctx_set_pagesize(codec_ctx *ctx, int size) {
  if(!((size != 0) && ((size & (size - 1)) == 0)) || size < 512 || size > 65536) {
    CODEC_TRACE(("cipher_page_size not a power of 2 and between 512 and 65536 inclusive\n"));
    return SQLITE_ERROR;
  }
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

void sqlcipher_set_default_pagesize(int page_size) {
  default_page_size = page_size;
}

int sqlcipher_get_default_pagesize() {
  return default_page_size;
}

void sqlcipher_set_mem_security(int on) {
  mem_security_on = on;
  mem_security_activated = 0;
}

int sqlcipher_get_mem_security() {
  return mem_security_on && mem_security_activated;
}


int sqlcipher_codec_ctx_init(codec_ctx **iCtx, Db *pDb, Pager *pPager, sqlite3_file *fd, const void *zKey, int nKey) {
  int rc;
  codec_ctx *ctx;

  CODEC_TRACE("sqlcipher_codec_ctx_init: allocating context\n");

  *iCtx = sqlcipher_malloc(sizeof(codec_ctx));
  ctx = *iCtx;

  if(ctx == NULL) return SQLITE_NOMEM;

  ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */

  /* allocate space for salt data. Then read the first 16 bytes 
       directly off the database file. This is the salt for the
       key derivation function. If we get a short read allocate
       a new random salt value */
  CODEC_TRACE("sqlcipher_codec_ctx_init: allocating kdf_salt\n");
  ctx->kdf_salt_sz = FILE_HEADER_SZ;
  ctx->kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz);
  if(ctx->kdf_salt == NULL) return SQLITE_NOMEM;

  /* allocate space for separate hmac salt data. We want the
     HMAC derivation salt to be different than the encryption
     key derivation salt */
  CODEC_TRACE("sqlcipher_codec_ctx_init: allocating hmac_kdf_salt\n");
  ctx->hmac_kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz);
  if(ctx->hmac_kdf_salt == NULL) return SQLITE_NOMEM;

  /* setup default flags */
  ctx->flags = default_flags;

  /* read salt from header, if present */
  CODEC_TRACE("sqlcipher_codec_ctx_init: reading file header\n");
  if(fd == NULL || sqlite3OsRead(fd, ctx->kdf_salt, ctx->kdf_salt_sz, 0) != SQLITE_OK) {
    ctx->need_kdf_salt = 1;
  }

  /* setup the crypto provider  */
  CODEC_TRACE("sqlcipher_codec_ctx_init: allocating provider\n");
  ctx->provider = (sqlcipher_provider *) sqlcipher_malloc(sizeof(sqlcipher_provider));
  if(ctx->provider == NULL) return SQLITE_NOMEM;

  /* make a copy of the provider to be used for the duration of the context */
  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: entering sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
  sqlite3_mutex_enter(sqlcipher_provider_mutex);
  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: entered sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);

  memcpy(ctx->provider, default_provider, sizeof(sqlcipher_provider));

  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: leaving sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);
  sqlite3_mutex_leave(sqlcipher_provider_mutex);
  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: left sqlcipher provider mutex %p\n", sqlcipher_provider_mutex);

  CODEC_TRACE("sqlcipher_codec_ctx_init: calling provider ctx_init\n");
  if((rc = ctx->provider->ctx_init(&ctx->provider_ctx)) != SQLITE_OK) return rc;

  /* setup the cipher to establish the key_sz, iv_sz, etc */
  CODEC_TRACE("sqlcipher_codec_ctx_init: setting cipher\n");
  if((rc = sqlcipher_codec_ctx_set_cipher(ctx, CIPHER)) != SQLITE_OK) return rc;

  /* establic the size for a hex-formated key specification, containing the 
     raw encryption key and the salt used to generate it format. will be x'hexkey...hexsalt'
     so oversize by 3 bytes */ 
  ctx->keyspec_sz = ((ctx->key_sz + ctx->kdf_salt_sz) * 2) + 3;

  /*
     Always overwrite page size and set to the default because the first page of the database
     in encrypted and thus sqlite can't effectively determine the pagesize. this causes an issue in 
     cases where bytes 16 & 17 of the page header are a power of 2 as reported by John Lehman
  */
  CODEC_TRACE("sqlcipher_codec_ctx_init: calling sqlcipher_codec_ctx_set_pagesize with %d\n", default_page_size);
  if((rc = sqlcipher_codec_ctx_set_pagesize(ctx, default_page_size)) != SQLITE_OK) return rc;

  /* establish settings for the KDF iterations and fast (HMAC) KDF iterations */
  CODEC_TRACE("sqlcipher_codec_ctx_init: setting default_kdf_iter\n");
  if((rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, default_kdf_iter)) != SQLITE_OK) return rc;

  CODEC_TRACE("sqlcipher_codec_ctx_init: setting fast_kdf_iter\n");
  if((rc = sqlcipher_codec_ctx_set_fast_kdf_iter(ctx, FAST_PBKDF2_ITER)) != SQLITE_OK) return rc;

  /* set the default HMAC and KDF algorithms which will determine the reserve size */
  CODEC_TRACE("sqlcipher_codec_ctx_init: calling sqlcipher_codec_ctx_set_hmac_algorithm with %d\n", default_hmac_algorithm);
  if((rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, default_hmac_algorithm)) != SQLITE_OK) return rc;

  /* Note that use_hmac is a special case that requires recalculation of page size
     so we call set_use_hmac to perform setup */
  CODEC_TRACE("sqlcipher_codec_ctx_init: setting use_hmac\n");
  if((rc = sqlcipher_codec_ctx_set_use_hmac(ctx, default_flags & CIPHER_FLAG_HMAC)) != SQLITE_OK) return rc;

  CODEC_TRACE("sqlcipher_codec_ctx_init: calling sqlcipher_codec_ctx_set_kdf_algorithm with %d\n", default_kdf_algorithm);
  if((rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, default_kdf_algorithm)) != SQLITE_OK) return rc;

  /* setup the default plaintext header size */
  CODEC_TRACE("sqlcipher_codec_ctx_init: calling sqlcipher_codec_ctx_set_plaintext_header_size with %d\n", default_plaintext_header_sz);
  if((rc = sqlcipher_codec_ctx_set_plaintext_header_size(ctx, default_plaintext_header_sz)) != SQLITE_OK) return rc;

  /* initialize the read and write sub-contexts. this must happen after key_sz is established  */
  CODEC_TRACE("sqlcipher_codec_ctx_init: initializing read_ctx\n");
  if((rc = sqlcipher_cipher_ctx_init(ctx, &ctx->read_ctx)) != SQLITE_OK) return rc; 

  CODEC_TRACE("sqlcipher_codec_ctx_init: initializing write_ctx\n");
  if((rc = sqlcipher_cipher_ctx_init(ctx, &ctx->write_ctx)) != SQLITE_OK) return rc; 

  /* set the key material on one of the sub cipher contexts and sync them up */
  CODEC_TRACE("sqlcipher_codec_ctx_init: setting pass key\n");
  if((rc = sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, 0)) != SQLITE_OK) return rc;

  CODEC_TRACE("sqlcipher_codec_ctx_init: copying write_ctx to read_ctx\n");
  if((rc = sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx)) != SQLITE_OK) return rc;

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx, including the allocated
  * read_ctx and write_ctx.
  */
void sqlcipher_codec_ctx_free(codec_ctx **iCtx) {
  codec_ctx *ctx = *iCtx;
  CODEC_TRACE("codec_ctx_free: entered iCtx=%p\n", iCtx);
  sqlcipher_free(ctx->kdf_salt, ctx->kdf_salt_sz);
  sqlcipher_free(ctx->hmac_kdf_salt, ctx->kdf_salt_sz);
  sqlcipher_free(ctx->buffer, 0);

  ctx->provider->ctx_free(&ctx->provider_ctx);
  sqlcipher_free(ctx->provider, sizeof(sqlcipher_provider)); 

  sqlcipher_cipher_ctx_free(ctx, &ctx->read_ctx);
  sqlcipher_cipher_ctx_free(ctx, &ctx->write_ctx);
  sqlcipher_free(ctx, sizeof(codec_ctx)); 
}

/** convert a 32bit unsigned integer to little endian byte ordering */
static void sqlcipher_put4byte_le(unsigned char *p, u32 v) { 
  p[0] = (u8)v;
  p[1] = (u8)(v>>8);
  p[2] = (u8)(v>>16);
  p[3] = (u8)(v>>24);
}

static int sqlcipher_page_hmac(codec_ctx *ctx, cipher_ctx *c_ctx, Pgno pgno, unsigned char *in, int in_sz, unsigned char *out) {
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
    ctx->provider_ctx, ctx->hmac_algorithm, c_ctx->hmac_key,
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
  int size;

  /* calculate some required positions into various buffers */
  size = page_sz - ctx->reserve_sz; /* adjust size to useable size and memset reserve at end of page */
  iv_out = out + size;
  iv_in = in + size;

  /* hmac will be written immediately after the initialization vector. the remainder of the page reserve will contain
     random bytes. note, these pointers are only valid when using hmac */
  hmac_in = in + size + ctx->iv_sz; 
  hmac_out = out + size + ctx->iv_sz;
  out_start = out; /* note the original position of the output buffer pointer, as out will be rewritten during encryption */

  CODEC_TRACE("codec_cipher:entered pgno=%d, mode=%d, size=%d\n", pgno, mode, size);
  CODEC_HEXDUMP("codec_cipher: input page data", in, page_sz);

  /* the key size should never be zero. If it is, error out. */
  if(ctx->key_sz == 0) {
    CODEC_TRACE("codec_cipher: error possible context corruption, key_sz is zero for pgno=%d\n", pgno);
    sqlcipher_memset(out, 0, page_sz); 
    return SQLITE_ERROR;
  } 

  if(mode == CIPHER_ENCRYPT) {
    /* start at front of the reserve block, write random data to the end */
    if(ctx->provider->random(ctx->provider_ctx, iv_out, ctx->reserve_sz) != SQLITE_OK) return SQLITE_ERROR; 
  } else { /* CIPHER_DECRYPT */
    memcpy(iv_out, iv_in, ctx->iv_sz); /* copy the iv from the input to output buffer */
  } 

  if((ctx->flags & CIPHER_FLAG_HMAC) && (mode == CIPHER_DECRYPT) && !ctx->skip_read_hmac) {
    if(sqlcipher_page_hmac(ctx, c_ctx, pgno, in, size + ctx->iv_sz, hmac_out) != SQLITE_OK) {
      sqlcipher_memset(out, 0, page_sz); 
      CODEC_TRACE("codec_cipher: hmac operations failed for pgno=%d\n", pgno);
      return SQLITE_ERROR;
    }

    CODEC_TRACE("codec_cipher: comparing hmac on in=%p out=%p hmac_sz=%d\n", hmac_in, hmac_out, ctx->hmac_sz);
    if(sqlcipher_memcmp(hmac_in, hmac_out, ctx->hmac_sz) != 0) { /* the hmac check failed */ 
      if(sqlcipher_ismemset(in, 0, page_sz) == 0) {
        /* first check if the entire contents of the page is zeros. If so, this page 
           resulted from a short read (i.e. sqlite attempted to pull a page after the end of the file. these 
           short read failures must be ignored for autovaccum mode to work so wipe the output buffer 
           and return SQLITE_OK to skip the decryption step. */
        CODEC_TRACE("codec_cipher: zeroed page (short read) for pgno %d, encryption but returning SQLITE_OK\n", pgno);
        sqlcipher_memset(out, 0, page_sz); 
        return SQLITE_OK;
      } else {
        /* if the page memory is not all zeros, it means the there was data and a hmac on the page. 
           since the check failed, the page was either tampered with or corrupted. wipe the output buffer,
           and return SQLITE_ERROR to the caller */
        CODEC_TRACE("codec_cipher: hmac check failed for pgno=%d returning SQLITE_ERROR\n", pgno);
        sqlcipher_memset(out, 0, page_sz); 
        return SQLITE_ERROR;
      }
    }
  } 
  
  ctx->provider->cipher(ctx->provider_ctx, mode, c_ctx->key, ctx->key_sz, iv_out, in, size, out);

  if((ctx->flags & CIPHER_FLAG_HMAC) && (mode == CIPHER_ENCRYPT)) {
    sqlcipher_page_hmac(ctx, c_ctx, pgno, out_start, size + ctx->iv_sz, hmac_out); 
  }

  CODEC_HEXDUMP("codec_cipher: output page data", out_start, page_sz);

  return SQLITE_OK;
}

/**
  * Derive an encryption key for a cipher contex key based on the raw password.
  *
  * If the raw key data is formated as x'hex' and there are exactly enough hex chars to fill
  * the key (i.e 64 hex chars for a 256 bit key) then the key data will be used directly. 

  * Else, if the raw key data is formated as x'hex' and there are exactly enough hex chars to fill
  * the key and the salt (i.e 92 hex chars for a 256 bit key and 16 byte salt) then it will be unpacked
  * as the key followed by the salt.
  * 
  * Otherwise, a key data will be derived using PBKDF2
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_ERROR if the key could't be derived (for instance if pass is NULL or pass_sz is 0)
  */
static int sqlcipher_cipher_ctx_key_derive(codec_ctx *ctx, cipher_ctx *c_ctx) {
  int rc;
  CODEC_TRACE("cipher_ctx_key_derive: entered c_ctx->pass=%s, c_ctx->pass_sz=%d \
                ctx->kdf_salt=%p ctx->kdf_salt_sz=%d c_ctx->kdf_iter=%d \
                ctx->hmac_kdf_salt=%p, c_ctx->fast_kdf_iter=%d ctx->key_sz=%d\n", 
                c_ctx->pass, c_ctx->pass_sz, ctx->kdf_salt, ctx->kdf_salt_sz, c_ctx->kdf_iter, 
                ctx->hmac_kdf_salt, c_ctx->fast_kdf_iter, ctx->key_sz); 
                
  
  if(c_ctx->pass && c_ctx->pass_sz) { // if pass is not null

    if(ctx->need_kdf_salt) {
      if(ctx->provider->random(ctx->provider_ctx, ctx->kdf_salt, ctx->kdf_salt_sz) != SQLITE_OK) return SQLITE_ERROR;
      ctx->need_kdf_salt = 0;
    }
    if (c_ctx->pass_sz == ((ctx->key_sz * 2) + 3) && sqlite3StrNICmp((const char *)c_ctx->pass ,"x'", 2) == 0 && cipher_isHex(c_ctx->pass + 2, ctx->key_sz * 2)) { 
      int n = c_ctx->pass_sz - 3; /* adjust for leading x' and tailing ' */
      const unsigned char *z = c_ctx->pass + 2; /* adjust lead offset of x' */
      CODEC_TRACE("cipher_ctx_key_derive: using raw key from hex\n");
      cipher_hex2bin(z, n, c_ctx->key);
    } else if (c_ctx->pass_sz == (((ctx->key_sz + ctx->kdf_salt_sz) * 2) + 3) && sqlite3StrNICmp((const char *)c_ctx->pass ,"x'", 2) == 0 && cipher_isHex(c_ctx->pass + 2, (ctx->key_sz + ctx->kdf_salt_sz) * 2)) { 
      const unsigned char *z = c_ctx->pass + 2; /* adjust lead offset of x' */
      CODEC_TRACE("cipher_ctx_key_derive: using raw key from hex\n"); 
      cipher_hex2bin(z, (ctx->key_sz * 2), c_ctx->key);
      cipher_hex2bin(z + (ctx->key_sz * 2), (ctx->kdf_salt_sz * 2), ctx->kdf_salt);
    } else { 
      CODEC_TRACE("cipher_ctx_key_derive: deriving key using full PBKDF2 with %d iterations\n", c_ctx->kdf_iter); 
      ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->pass, c_ctx->pass_sz, 
                    ctx->kdf_salt, ctx->kdf_salt_sz, ctx->kdf_iter,
                    ctx->key_sz, c_ctx->key);
    }

    /* set the context "keyspec" containing the hex-formatted key and salt to be used when attaching databases */
    if((rc = sqlcipher_cipher_ctx_set_keyspec(ctx, c_ctx, c_ctx->key)) != SQLITE_OK) return rc;

    /* if this context is setup to use hmac checks, generate a seperate and different 
       key for HMAC. In this case, we use the output of the previous KDF as the input to 
       this KDF run. This ensures a distinct but predictable HMAC key. */
    if(ctx->flags & CIPHER_FLAG_HMAC) {
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

      CODEC_TRACE("cipher_ctx_key_derive: deriving hmac key from encryption key using PBKDF2 with %d iterations\n", 
        c_ctx->fast_kdf_iter); 

      
      ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->key, ctx->key_sz, 
                    ctx->hmac_kdf_salt, ctx->kdf_salt_sz, ctx->fast_kdf_iter,
                    ctx->key_sz, c_ctx->hmac_key); 
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
      /* the relevant parameters are the same, just copy read key */
      if(sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx) != SQLITE_OK) return SQLITE_ERROR;
    } else {
      if(sqlcipher_cipher_ctx_key_derive(ctx, ctx->write_ctx) != SQLITE_OK) return SQLITE_ERROR;
    }
  }

  /* TODO: wipe and free passphrase after key derivation */
  if(ctx->store_pass  != 1) {
    sqlcipher_cipher_ctx_set_pass(ctx->read_ctx, NULL, 0);
    sqlcipher_cipher_ctx_set_pass(ctx->write_ctx, NULL, 0);
  }

  return SQLITE_OK; 
}

int sqlcipher_codec_key_copy(codec_ctx *ctx, int source) {
  if(source == CIPHER_READ_CTX) { 
      return sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx); 
  } else {
      return sqlcipher_cipher_ctx_copy(ctx, ctx->read_ctx, ctx->write_ctx); 
  }
}

const char* sqlcipher_codec_get_cipher_provider(codec_ctx *ctx) {
  return ctx->provider->get_provider_name(ctx->provider_ctx);
}


static int sqlcipher_check_connection(const char *filename, char *key, int key_sz, char *sql, int *user_version) {
  int rc;
  sqlite3 *db = NULL;
  sqlite3_stmt *statement = NULL;
  char *query_user_version = "PRAGMA user_version;";
  
  rc = sqlite3_open(filename, &db);
  if(rc != SQLITE_OK){
    goto cleanup;
  }
  rc = sqlite3_key(db, key, key_sz);
  if(rc != SQLITE_OK){
    goto cleanup;
  }
  rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    goto cleanup;
  }
  rc = sqlite3_prepare(db, query_user_version, -1, &statement, NULL);
  if(rc != SQLITE_OK){
    goto cleanup;
  }
  rc = sqlite3_step(statement);
  if(rc == SQLITE_ROW){
    *user_version = sqlite3_column_int(statement, 0);
    rc = SQLITE_OK;
  }
  
cleanup:
  if(statement){
    sqlite3_finalize(statement);
  }
  if(db){
    sqlite3_close(db);
  }
  return rc;
}

int sqlcipher_codec_ctx_migrate(codec_ctx *ctx) {
  u32 meta;
  int i, password_sz, key_sz, saved_flags, saved_nChange, saved_nTotalChange, nRes, user_version = 0, upgrade_from = 0, rc = 0;
  u8 saved_mTrace;
  int (*saved_xTrace)(u32,void*,void*,void*); /* Saved db->xTrace */
  Db *pDb = 0;
  sqlite3 *db = ctx->pBt->db;
  const char *db_filename = sqlite3_db_filename(db, "main");
  char *migrated_db_filename = sqlite3_mprintf("%s-migrated", db_filename);
  char *v1_pragmas = "PRAGMA cipher_use_hmac = OFF; PRAGMA kdf_iter = 4000; PRAGMA cipher_page_size = 1024; PRAGMA cipher_hmac_algorithm = HMAC_SHA1; PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;"; 
  char *v2_pragmas = "PRAGMA kdf_iter = 4000; PRAGMA cipher_page_size = 1024; PRAGMA cipher_hmac_algorithm = HMAC_SHA1; PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;";
  char *v3_pragmas = "PRAGMA kdf_iter = 64000; PRAGMA cipher_page_size = 1024; PRAGMA cipher_hmac_algorithm = HMAC_SHA1; PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;";
  char *set_user_version, *key;
  Btree *pDest = NULL, *pSrc = NULL;
  static const unsigned char aCopy[] = {
    BTREE_SCHEMA_VERSION,     1,  /* Add one to the old schema cookie */
    BTREE_DEFAULT_CACHE_SIZE, 0,  /* Preserve the default page cache size */
    BTREE_TEXT_ENCODING,      0,  /* Preserve the text encoding */
    BTREE_USER_VERSION,       0,  /* Preserve the user version */
    BTREE_APPLICATION_ID,     0,  /* Preserve the application id */
  };

  rc = user_version = upgrade_from = 0;

  key_sz = ctx->read_ctx->pass_sz + 1;
  key = sqlcipher_malloc(key_sz);
  memset(key, 0, key_sz);
  memcpy(key, ctx->read_ctx->pass, ctx->read_ctx->pass_sz);

  if(db_filename){
    const char* commands[4];
    char *attach_command = sqlite3_mprintf("ATTACH DATABASE '%s-migrated' as migrate KEY '%q';",
                                            db_filename, key);

    int rc = sqlcipher_check_connection(db_filename, key, ctx->read_ctx->pass_sz, "", &user_version);
    if(rc == SQLITE_OK){
      CODEC_TRACE("No upgrade required - exiting\n");
      goto exit;
    }

    /* Version 3 - check for 64k with hmac format and 1024 page size */
    rc = sqlcipher_check_connection(db_filename, key, ctx->read_ctx->pass_sz, v3_pragmas, &user_version);
    if(rc == SQLITE_OK) {
      CODEC_TRACE("Version 3 format found\n");
      upgrade_from = 3;
    }
    
    /* Version 2 - check for 4k with hmac format and 1024 page size */
    rc = sqlcipher_check_connection(db_filename, key, ctx->read_ctx->pass_sz, v2_pragmas, &user_version);
    if(rc == SQLITE_OK) {
      CODEC_TRACE("Version 2 format found\n");
      upgrade_from = 2;
    }

    /* Version 1 - check no HMAC, 4k KDF, and 1024 page size */
    rc = sqlcipher_check_connection(db_filename, key, ctx->read_ctx->pass_sz, v1_pragmas, &user_version);
    if(rc == SQLITE_OK) {
      CODEC_TRACE("Version 1 format found\n");
      upgrade_from = 1;
    }

    set_user_version = sqlite3_mprintf("PRAGMA migrate.user_version = %d;", user_version);
    switch(upgrade_from) {
      case 1:
        commands[0] = v1_pragmas;
        break;
      case 2:
        commands[0] = v2_pragmas;
        break;
      case 3:
        commands[0] = v3_pragmas;
        break;
      default:
        CODEC_TRACE("Upgrade format not determined\n");
        goto handle_error;
    }
    commands[1] = attach_command;
    commands[2] = "SELECT sqlcipher_export('migrate');";
    commands[3] = set_user_version;
      
    for(i = 0; i < ArraySize(commands); i++){
      rc = sqlite3_exec(db, commands[i], NULL, NULL, NULL);
      if(rc != SQLITE_OK){
        CODEC_TRACE("migration step %d failed error code %d\n", i, rc);
        break;
      }
    }
    sqlite3_free(attach_command);
    sqlite3_free(set_user_version);
    sqlcipher_free(key, key_sz);
    
    if(rc == SQLITE_OK){

      if( !db->autoCommit ){
        CODEC_TRACE("cannot migrate from within a transaction");
        goto handle_error;
      }
      if( db->nVdbeActive>1 ){
        CODEC_TRACE("cannot migrate - SQL statements in progress");
        goto handle_error;
      }

      /* Save the current value of the database flags so that it can be
      ** restored before returning. Then set the writable-schema flag, and
      ** disable CHECK and foreign key constraints.  */
      saved_flags = db->flags;
      saved_nChange = db->nChange;
      saved_nTotalChange = db->nTotalChange;
      saved_xTrace = db->xTrace;
      saved_mTrace = db->mTrace;
      db->flags |= SQLITE_WriteSchema | SQLITE_IgnoreChecks | SQLITE_PreferBuiltin;
      db->flags &= ~(SQLITE_ForeignKeys | SQLITE_ReverseOrder);
      db->xTrace = 0;
      db->mTrace = 0;
      pDest = db->aDb[0].pBt;
      pDb = &(db->aDb[db->nDb-1]);
      pSrc = pDb->pBt;

      nRes = sqlite3BtreeGetOptimalReserve(pSrc); 
      rc = sqlite3BtreeSetPageSize(pDest, default_page_size, nRes, 0);
      if( rc!=SQLITE_OK ) goto handle_error;
      CODEC_TRACE("set BTree page size to %d res %d rc %d\n", default_page_size, nRes, rc);

      rc = sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
      if( rc!=SQLITE_OK ) goto handle_error;

      sqlite3pager_truncate(pDest->pBt->pPager, 0);

      rc = sqlite3BtreeBeginTrans(pSrc, 2);
      if( rc!=SQLITE_OK ) goto handle_error;

      rc = sqlite3BtreeBeginTrans(pDest, 2);
      if( rc!=SQLITE_OK ) goto handle_error;

      assert( 1==sqlite3BtreeIsInTrans(pDest) );
      assert( 1==sqlite3BtreeIsInTrans(pSrc) );

      CODEC_TRACE("started transactions\n");

      sqlite3CodecGetKey(db, db->nDb - 1, (void**)&key, &password_sz);
      sqlite3CodecAttach(db, 0, key, password_sz);
      sqlite3pager_get_codec(pDest->pBt->pPager, (void**)&ctx);

      ctx->skip_read_hmac = 1;      

      for(i=0; i<ArraySize(aCopy); i+=2){
        sqlite3BtreeGetMeta(pSrc, aCopy[i], &meta);
        rc = sqlite3BtreeUpdateMeta(pDest, aCopy[i], meta+aCopy[i+1]);
        CODEC_TRACE("applied metadata %d %d\n",i, rc);
        if( NEVER(rc!=SQLITE_OK) ) goto handle_error; 
      }
      CODEC_TRACE("finished applied metadata\n");

      rc = sqlite3BtreeCopyFile(pDest, pSrc);
      ctx->skip_read_hmac = 0;
      if( rc!=SQLITE_OK ) goto handle_error;
      CODEC_TRACE("copied btree %d\n", rc);

      rc = sqlite3BtreeCommit(pDest);
      if( rc!=SQLITE_OK ) goto handle_error;
      CODEC_TRACE("committed destination transaction %d\n", rc);

      db->flags = saved_flags;
      db->nChange = saved_nChange;
      db->nTotalChange = saved_nTotalChange;
      db->xTrace = saved_xTrace;
      db->mTrace = saved_mTrace;
      db->autoCommit = 1;
      sqlite3BtreeClose(pDb->pBt);
      pDb->pBt = 0;
      pDb->pSchema = 0;
      sqlite3ResetAllSchemasOfConnection(db);
      db->pVfs->xDelete(db->pVfs, migrated_db_filename, 0);
      sqlite3_free(migrated_db_filename);
    } else {
      CODEC_TRACE("*** migration failure** error code: %d\n", rc);
    }
    
  }
  goto exit;

handle_error:
  if(pDest) sqlite3BtreeRollback(pDest, SQLITE_OK, 0);

  CODEC_TRACE("An error occurred attempting to migrate the database\n");
  rc = SQLITE_ERROR;

exit:
  return rc;
}

int sqlcipher_codec_add_random(codec_ctx *ctx, const char *zRight, int random_sz){
  const char *suffix = &zRight[random_sz-1];
  int n = random_sz - 3; /* adjust for leading x' and tailing ' */
  if (n > 0 &&
      sqlite3StrNICmp((const char *)zRight ,"x'", 2) == 0 &&
      sqlite3StrNICmp(suffix, "'", 1) == 0 &&
      n % 2 == 0) {
    int rc = 0;
    int buffer_sz = n / 2;
    unsigned char *random;
    const unsigned char *z = (const unsigned char *)zRight + 2; /* adjust lead offset of x' */
    CODEC_TRACE("sqlcipher_codec_add_random: using raw random blob from hex\n");
    random = sqlcipher_malloc(buffer_sz);
    memset(random, 0, buffer_sz);
    cipher_hex2bin(z, n, random);
    rc = ctx->provider->add_random(ctx->provider_ctx, random, buffer_sz);
    sqlcipher_free(random, buffer_sz);
    return rc;
  }
  return SQLITE_ERROR;
}

static void sqlcipher_profile_callback(void *file, const char *sql, sqlite3_uint64 run_time){
  FILE *f = (FILE*)file;
  double elapsed = run_time/1000000.0;
  if(f) fprintf(f, "Elapsed time:%.3f ms - %s\n", elapsed, sql);
}

int sqlcipher_cipher_profile(sqlite3 *db, const char *destination){
#if defined(SQLITE_OMIT_TRACE) || defined(SQLITE_OMIT_DEPRECATED)
  return SQLITE_ERROR;
#else
  FILE *f;
  if(sqlite3StrICmp(destination, "stdout") == 0){
    f = stdout;
  }else if(sqlite3StrICmp(destination, "stderr") == 0){
    f = stderr;
  }else if(sqlite3StrICmp(destination, "off") == 0){
    f = 0;
  }else{
#if defined(_WIN32) && (__STDC_VERSION__ > 199901L) || defined(SQLITE_OS_WINRT)
    if(fopen_s(&f, destination, "a") != 0){
#else
    f = fopen(destination, "a");
    if(f == 0){
#endif    
    return SQLITE_ERROR;
  }

  }
  sqlite3_profile(db, sqlcipher_profile_callback, f);
  return SQLITE_OK;
#endif
}

int sqlcipher_codec_fips_status(codec_ctx *ctx) {
  return ctx->provider->fips_status(ctx->provider_ctx);
}

const char* sqlcipher_codec_get_provider_version(codec_ctx *ctx) {
  return ctx->provider->get_provider_version(ctx->provider_ctx);
}

int sqlcipher_codec_hmac(const codec_ctx *ctx, const unsigned char *hmac_key, int key_sz,
                         unsigned char* in, int in_sz, unsigned char *in2, int in2_sz,
                         unsigned char *out) {
  ctx->provider->hmac(ctx->provider_ctx, SQLCIPHER_HMAC_SHA1, (unsigned char *)hmac_key, key_sz, in, in_sz, in2, in2_sz, out);
  return SQLITE_OK;
}


#endif
/* END SQLCIPHER */
