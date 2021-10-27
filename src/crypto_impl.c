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
static volatile int mem_security_initialized = 0;
static volatile int mem_security_activated = 0;
static volatile unsigned int sqlcipher_activate_count = 0;
static volatile sqlite3_mem_methods default_mem_methods;
static sqlcipher_provider *default_provider = NULL;

static sqlite3_mutex* sqlcipher_static_mutex[SQLCIPHER_MUTEX_COUNT];

sqlite3_mutex* sqlcipher_mutex(int mutex) {
  if(mutex < 0 || mutex >= SQLCIPHER_MUTEX_COUNT) return NULL;
  return sqlcipher_static_mutex[mutex];
}

static int sqlcipher_mem_init(void *pAppData) {
  return default_mem_methods.xInit(pAppData);
}
static void sqlcipher_mem_shutdown(void *pAppData) {
  default_mem_methods.xShutdown(pAppData);
}
static void *sqlcipher_mem_malloc(int n) {
  void *ptr = default_mem_methods.xMalloc(n);
  if(mem_security_on) {
    CODEC_TRACE_MEMORY("sqlcipher_mem_malloc: calling sqlcipher_mlock(%p,%d)\n", ptr, n);
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
    CODEC_TRACE_MEMORY("sqlcipher_mem_free: calling sqlcipher_memset(%p,0,%d) and sqlcipher_munlock(%p, %d) \n", p, sz, p, sz);
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
  if(mem_security_initialized) return;
  if(sqlite3_config(SQLITE_CONFIG_GETMALLOC, &default_mem_methods) != SQLITE_OK ||
     sqlite3_config(SQLITE_CONFIG_MALLOC, &sqlcipher_mem_methods)  != SQLITE_OK) {
    mem_security_on = mem_security_activated = 0;
  }
  mem_security_initialized = 1;
}

int sqlcipher_register_provider(sqlcipher_provider *p) {
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: entering SQLCIPHER_MUTEX_PROVIDER\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: entered SQLCIPHER_MUTEX_PROVIDER\n");

  if(default_provider != NULL && default_provider != p) {
    /* only free the current registerd provider if it has been initialized
       and it isn't a pointer to the same provider passed to the function
       (i.e. protect against a caller calling register twice for the same provider) */
    sqlcipher_free(default_provider, sizeof(sqlcipher_provider));
  }
  default_provider = p;   
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: leaving SQLCIPHER_MUTEX_PROVIDER\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
  CODEC_TRACE_MUTEX("sqlcipher_register_provider: left SQLCIPHER_MUTEX_PROVIDER\n");

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

  /* allocate new mutexes */
  if(sqlcipher_activate_count == 0) {
    int i;
    for(i = 0; i < SQLCIPHER_MUTEX_COUNT; i++) {
      sqlcipher_static_mutex[i] = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
    }
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
#elif defined (SQLCIPHER_CRYPTO_NSS)
    extern int sqlcipher_nss_setup(sqlcipher_provider *p);
    sqlcipher_nss_setup(p);
#elif defined (SQLCIPHER_CRYPTO_OPENSSL)
    extern int sqlcipher_openssl_setup(sqlcipher_provider *p);
    sqlcipher_openssl_setup(p);
#elif defined (SQLCIPHER_CRYPTO_SODIUM)
    extern int sqlcipher_sodium_setup(sqlcipher_provider *p);
    sqlcipher_sodium_setup(p);
#else
#error "NO DEFAULT SQLCIPHER CRYPTO PROVIDER DEFINED"
#endif
    CODEC_TRACE("sqlcipher_activate: calling sqlcipher_register_provider(%p)\n", p);
#ifdef SQLCIPHER_EXT
    sqlcipher_ext_provider_setup(p);
#endif
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

    CODEC_TRACE_MUTEX("sqlcipher_deactivate: entering SQLCIPHER_MUTEX_PROVIDER\n");
    sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: entered SQLCIPHER_MUTEX_PROVIDER\n");

    if(default_provider != NULL) {
      sqlcipher_free(default_provider, sizeof(sqlcipher_provider));
      default_provider = NULL;
    }

    CODEC_TRACE_MUTEX("sqlcipher_deactivate: leaving SQLCIPHER_MUTEX_PROVIDER\n");
    sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
    CODEC_TRACE_MUTEX("sqlcipher_deactivate: left SQLCIPHER_MUTEX_PROVIDER\n");

#ifdef SQLCIPHER_EXT
    sqlcipher_ext_provider_destroy();
#endif

    /* last connection closed, free mutexes */
    if(sqlcipher_activate_count == 0) {
      int i;
      for(i = 0; i < SQLCIPHER_MUTEX_COUNT; i++) {
        sqlite3_mutex_free(sqlcipher_static_mutex[i]);
      }
    }
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
void* sqlcipher_memset(void *v, unsigned char value, u64 len) {
  u64 i = 0;
  volatile unsigned char *a = v;

  if (v == NULL) return v;

  CODEC_TRACE_MEMORY("sqlcipher_memset: setting %p[0-%llu]=%d)\n", a, len, value);
  for(i = 0; i < len; i++) {
    a[i] = value;
  }

  return v;
}

/* constant time memory check tests every position of a memory segement
   matches a single value (i.e. the memory is all zeros)
   returns 0 if match, 1 of no match */
int sqlcipher_ismemset(const void *v, unsigned char value, u64 len) {
  const unsigned char *a = v;
  u64 i = 0, result = 0;

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

void sqlcipher_mlock(void *ptr, u64 sz) {
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) 
  int rc;
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  unsigned long offset = (unsigned long) ptr % pagesize;

  if(ptr == NULL || sz == 0) return;

  CODEC_TRACE_MEMORY("sqlcipher_mem_lock: calling mlock(%p,%lu); _SC_PAGESIZE=%lu\n", ptr - offset, sz + offset, pagesize);
  rc = mlock(ptr - offset, sz + offset);
  if(rc!=0) {
    CODEC_TRACE_MEMORY("sqlcipher_mem_lock: mlock(%p,%lu) returned %d errno=%d\n", ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_APP))
  int rc;
  CODEC_TRACE("sqlcipher_mem_lock: calling VirtualLock(%p,%d)\n", ptr, sz);
  rc = VirtualLock(ptr, sz);
  if(rc==0) {
    CODEC_TRACE("sqlcipher_mem_lock: VirtualLock(%p,%d) returned %d LastError=%d\n", ptr, sz, rc, GetLastError());
  }
#endif
#endif
#endif
}

void sqlcipher_munlock(void *ptr, u64 sz) {
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) 
  int rc;
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  unsigned long offset = (unsigned long) ptr % pagesize;

  if(ptr == NULL || sz == 0) return;

  CODEC_TRACE_MEMORY("sqlcipher_mem_unlock: calling munlock(%p,%lu)\n", ptr - offset, sz + offset);
  rc = munlock(ptr - offset, sz + offset);
  if(rc!=0) {
    CODEC_TRACE_MEMORY("sqlcipher_mem_unlock: munlock(%p,%lu) returned %d errno=%d\n", ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_APP))
  int rc;
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
void sqlcipher_free(void *ptr, u64 sz) {
  CODEC_TRACE_MEMORY("sqlcipher_free: calling sqlcipher_memset(%p,0,%llu)\n", ptr, sz);
  sqlcipher_memset(ptr, 0, sz);
  sqlcipher_munlock(ptr, sz);
  sqlite3_free(ptr);
}

/**
  * allocate memory. Uses sqlite's internall malloc wrapper so memory can be 
  * reference counted and leak detection works. Unless compiled with OMIT_MEMLOCK
  * attempts to lock the memory pages so sensitive information won't be swapped
  */
void* sqlcipher_malloc(u64 sz) {
  void *ptr;
  CODEC_TRACE_MEMORY("sqlcipher_malloc: calling sqlite3Malloc(%llu)\n", sz);
  ptr = sqlite3Malloc(sz);
  CODEC_TRACE_MEMORY("sqlcipher_malloc: calling sqlcipher_memset(%p,0,%llu)\n", ptr, sz);
  sqlcipher_memset(ptr, 0, sz);
  sqlcipher_mlock(ptr, sz);
  return ptr;
}

char* sqlcipher_version() {
#ifdef CIPHER_VERSION_QUALIFIER
    char *version = sqlite3_mprintf("%s %s %s", CIPHER_XSTR(CIPHER_VERSION_NUMBER), CIPHER_XSTR(CIPHER_VERSION_QUALIFIER), CIPHER_XSTR(CIPHER_VERSION_BUILD));
#else
    char *version = sqlite3_mprintf("%s %s", CIPHER_XSTR(CIPHER_VERSION_NUMBER), CIPHER_XSTR(CIPHER_VERSION_BUILD));
#endif
    return version;
}

/**
  * Initialize new cipher_ctx struct. This function will allocate memory
  * for the cipher context and for the key
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_init(codec_ctx *ctx, cipher_ctx **iCtx) {
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
  int base_reserve = ctx->iv_sz; /* base reserve size will be IV only */ 
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

  target->key = key; /* restore pointer to previously allocated key data */
  memcpy(target->key, source->key, ctx->key_sz);

  target->hmac_key = hmac_key; /* restore pointer to previously allocated hmac key data */
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
  ctx->plaintext_header_sz = -1;
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
  sqlite3pager_error(ctx->pBt->pBt->pPager, error);
  ctx->pBt->pBt->db->errCode = error;
}

int sqlcipher_codec_ctx_get_reservesize(codec_ctx *ctx) {
  return ctx->reserve_sz;
}

void* sqlcipher_codec_ctx_get_data(codec_ctx *ctx) {
  return ctx->buffer;
}

static int sqlcipher_codec_ctx_init_kdf_salt(codec_ctx *ctx) {
  sqlite3_file *fd = sqlite3PagerFile(ctx->pBt->pBt->pPager);

  if(!ctx->need_kdf_salt) {
    return SQLITE_OK; /* don't reload salt when not needed */
  }

  /* read salt from header, if present, otherwise generate a new random salt */
  CODEC_TRACE("sqlcipher_codec_ctx_init_kdf_salt: obtaining salt\n");
  if(fd == NULL || fd->pMethods == 0 || sqlite3OsRead(fd, ctx->kdf_salt, ctx->kdf_salt_sz, 0) != SQLITE_OK) {
    CODEC_TRACE("sqlcipher_codec_ctx_init_kdf_salt: unable to read salt from file header, generating random\n");
    if(ctx->provider->random(ctx->provider_ctx, ctx->kdf_salt, ctx->kdf_salt_sz) != SQLITE_OK) return SQLITE_ERROR;
  }
  ctx->need_kdf_salt = 0;
  return SQLITE_OK; 
}

int sqlcipher_codec_ctx_set_kdf_salt(codec_ctx *ctx, unsigned char *salt, int size) {
  if(size >= ctx->kdf_salt_sz) {
    memcpy(ctx->kdf_salt, salt, ctx->kdf_salt_sz);
    ctx->need_kdf_salt = 0;
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

int sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx, void** salt) {
  int rc = SQLITE_OK;
  if(ctx->need_kdf_salt) {
    rc = sqlcipher_codec_ctx_init_kdf_salt(ctx);
  }
  *salt = ctx->kdf_salt;
  return rc;
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


int sqlcipher_codec_ctx_init(codec_ctx **iCtx, Db *pDb, Pager *pPager, const void *zKey, int nKey) {
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

  /* defer attempt to read KDF salt until first use */
  ctx->need_kdf_salt = 1;

  /* setup the crypto provider  */
  CODEC_TRACE("sqlcipher_codec_ctx_init: allocating provider\n");
  ctx->provider = (sqlcipher_provider *) sqlcipher_malloc(sizeof(sqlcipher_provider));
  if(ctx->provider == NULL) return SQLITE_NOMEM;

  /* make a copy of the provider to be used for the duration of the context */
  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: entering SQLCIPHER_MUTEX_PROVIDER\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: entered SQLCIPHER_MUTEX_PROVIDER\n");

  memcpy(ctx->provider, default_provider, sizeof(sqlcipher_provider));

  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: leaving SQLCIPHER_MUTEX_PROVIDER\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
  CODEC_TRACE_MUTEX("sqlcipher_codec_ctx_init: left SQLCIPHER_MUTEX_PROVIDER\n");

  CODEC_TRACE("sqlcipher_codec_ctx_init: calling provider ctx_init\n");
  if((rc = ctx->provider->ctx_init(&ctx->provider_ctx)) != SQLITE_OK) return rc;

  ctx->key_sz = ctx->provider->get_key_sz(ctx->provider_ctx);
  ctx->iv_sz = ctx->provider->get_iv_sz(ctx->provider_ctx);
  ctx->block_sz = ctx->provider->get_block_sz(ctx->provider_ctx);

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
  return ctx->provider->hmac(
    ctx->provider_ctx, ctx->hmac_algorithm, c_ctx->hmac_key,
    ctx->key_sz, in,
    in_sz, (unsigned char*) &pgno_raw,
    sizeof(pgno), out);
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
    goto error;
  } 

  if(mode == CIPHER_ENCRYPT) {
    /* start at front of the reserve block, write random data to the end */
    if(ctx->provider->random(ctx->provider_ctx, iv_out, ctx->reserve_sz) != SQLITE_OK) goto error;
  } else { /* CIPHER_DECRYPT */
    memcpy(iv_out, iv_in, ctx->iv_sz); /* copy the iv from the input to output buffer */
  } 

  if((ctx->flags & CIPHER_FLAG_HMAC) && (mode == CIPHER_DECRYPT) && !ctx->skip_read_hmac) {
    if(sqlcipher_page_hmac(ctx, c_ctx, pgno, in, size + ctx->iv_sz, hmac_out) != SQLITE_OK) {
      CODEC_TRACE("codec_cipher: hmac operation on decrypt failed for pgno=%d\n", pgno);
      goto error;
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
        goto error;
      }
    }
  } 
  
  if(ctx->provider->cipher(ctx->provider_ctx, mode, c_ctx->key, ctx->key_sz, iv_out, in, size, out) != SQLITE_OK) {
    CODEC_TRACE("codec_cipher: cipher operation mode=%d failed for pgno=%d returning SQLITE_ERROR\n", mode, pgno);
    goto error;
  };

  if((ctx->flags & CIPHER_FLAG_HMAC) && (mode == CIPHER_ENCRYPT)) {
    if(sqlcipher_page_hmac(ctx, c_ctx, pgno, out_start, size + ctx->iv_sz, hmac_out) != SQLITE_OK) {
      CODEC_TRACE("codec_cipher: hmac operation on encrypt failed for pgno=%d\n", pgno);
      goto error;
    }; 
  }

  CODEC_HEXDUMP("codec_cipher: output page data", out_start, page_sz);

  return SQLITE_OK;
error:
  sqlcipher_memset(out, 0, page_sz); 
  return SQLITE_ERROR;
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
                ctx->kdf_salt=%p ctx->kdf_salt_sz=%d ctx->kdf_iter=%d \
                ctx->hmac_kdf_salt=%p, ctx->fast_kdf_iter=%d ctx->key_sz=%d\n",
                c_ctx->pass, c_ctx->pass_sz, ctx->kdf_salt, ctx->kdf_salt_sz, ctx->kdf_iter,
                ctx->hmac_kdf_salt, ctx->fast_kdf_iter, ctx->key_sz);
                
  
  if(c_ctx->pass && c_ctx->pass_sz) {  /* if key material is present on the context for derivation */ 
   
    /* if necessary, initialize the salt from the header or random source */
    if(ctx->need_kdf_salt) {
      if((rc = sqlcipher_codec_ctx_init_kdf_salt(ctx)) != SQLITE_OK) return rc;
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
      CODEC_TRACE("cipher_ctx_key_derive: deriving key using full PBKDF2 with %d iterations\n", ctx->kdf_iter);
      if(ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->pass, c_ctx->pass_sz, 
                    ctx->kdf_salt, ctx->kdf_salt_sz, ctx->kdf_iter,
                    ctx->key_sz, c_ctx->key) != SQLITE_OK) return SQLITE_ERROR;
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
        ctx->fast_kdf_iter);

      
      if(ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->key, ctx->key_sz, 
                    ctx->hmac_kdf_salt, ctx->kdf_salt_sz, ctx->fast_kdf_iter,
                    ctx->key_sz, c_ctx->hmac_key) != SQLITE_OK) return SQLITE_ERROR;
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


static int sqlcipher_check_connection(const char *filename, char *key, int key_sz, char *sql, int *user_version, char** journal_mode) {
  int rc;
  sqlite3 *db = NULL;
  sqlite3_stmt *statement = NULL;
  char *query_journal_mode = "PRAGMA journal_mode;";
  char *query_user_version = "PRAGMA user_version;";
 
  rc = sqlite3_open(filename, &db);
  if(rc != SQLITE_OK) goto cleanup; 
    
  rc = sqlite3_key(db, key, key_sz);
  if(rc != SQLITE_OK) goto cleanup; 
    
  rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
  if(rc != SQLITE_OK) goto cleanup; 

  /* start by querying the user version. 
     this will fail if the key is incorrect */
  rc = sqlite3_prepare(db, query_user_version, -1, &statement, NULL);
  if(rc != SQLITE_OK) goto cleanup; 
    
  rc = sqlite3_step(statement);
  if(rc == SQLITE_ROW) {
    *user_version = sqlite3_column_int(statement, 0);
  } else {
    goto cleanup;
  }
  sqlite3_finalize(statement); 

  rc = sqlite3_prepare(db, query_journal_mode, -1, &statement, NULL);
  if(rc != SQLITE_OK) goto cleanup; 
    
  rc = sqlite3_step(statement);
  if(rc == SQLITE_ROW) {
    *journal_mode = sqlite3_mprintf("%s", sqlite3_column_text(statement, 0)); 
  } else {
    goto cleanup; 
  }
  rc = SQLITE_OK;
  /* cleanup will finalize open statement */
  
cleanup:
  if(statement) sqlite3_finalize(statement); 
  if(db) sqlite3_close(db); 
  return rc;
}

int sqlcipher_codec_ctx_integrity_check(codec_ctx *ctx, Parse *pParse, char *column) {
  Pgno page = 1;
  int rc = 0;
  char *result;
  unsigned char *hmac_out = NULL;
  sqlite3_file *fd = sqlite3PagerFile(ctx->pBt->pBt->pPager);
  i64 file_sz;

  Vdbe *v = sqlite3GetVdbe(pParse);
  sqlite3VdbeSetNumCols(v, 1);
  sqlite3VdbeSetColName(v, 0, COLNAME_NAME, column, SQLITE_STATIC);

  if(fd == NULL || fd->pMethods == 0) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "database file is undefined", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  if(!(ctx->flags & CIPHER_FLAG_HMAC)) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "HMAC is not enabled, unable to integrity check", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  if((rc = sqlcipher_codec_key_derive(ctx)) != SQLITE_OK) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "unable to derive keys", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  sqlite3OsFileSize(fd, &file_sz);
  hmac_out = sqlcipher_malloc(ctx->hmac_sz);

  for(page = 1; page <= file_sz / ctx->page_sz; page++) {
    int offset = (page - 1) * ctx->page_sz;
    int payload_sz = ctx->page_sz - ctx->reserve_sz + ctx->iv_sz;
    int read_sz = ctx->page_sz;

    /* skip integrity check on PAGER_MJ_PGNO since it will have no valid content */
    if(sqlite3pager_is_mj_pgno(ctx->pBt->pBt->pPager, page)) continue;

    if(page==1) {
      int page1_offset = ctx->plaintext_header_sz ? ctx->plaintext_header_sz : FILE_HEADER_SZ;
      read_sz = read_sz - page1_offset;
      payload_sz = payload_sz - page1_offset;
      offset += page1_offset;
    }

    sqlcipher_memset(ctx->buffer, 0, ctx->page_sz);
    sqlcipher_memset(hmac_out, 0, ctx->hmac_sz);
    if(sqlite3OsRead(fd, ctx->buffer, read_sz, offset) != SQLITE_OK) {
      result = sqlite3_mprintf("error reading %d bytes from file page %d at offset %d\n", read_sz, page, offset);
      sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
      sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    } else if(sqlcipher_page_hmac(ctx, ctx->read_ctx, page, ctx->buffer, payload_sz, hmac_out) != SQLITE_OK) {
      result = sqlite3_mprintf("HMAC operation failed for page %d", page);
      sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
      sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    } else if(sqlcipher_memcmp(ctx->buffer + payload_sz, hmac_out, ctx->hmac_sz) != 0) {
      result = sqlite3_mprintf("HMAC verification failed for page %d", page);
      sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
      sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    }
  }

  if(file_sz % ctx->page_sz != 0) {
    result = sqlite3_mprintf("page %d has an invalid size of %lld bytes", page, file_sz - ((file_sz / ctx->page_sz) * ctx->page_sz));
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
  }

cleanup:
  if(hmac_out != NULL) sqlcipher_free(hmac_out, ctx->hmac_sz);
  return SQLITE_OK;
}

int sqlcipher_codec_ctx_migrate(codec_ctx *ctx) {
  int i, pass_sz, keyspec_sz, nRes, user_version, rc, oflags;
  Db *pDb = 0;
  sqlite3 *db = ctx->pBt->db;
  const char *db_filename = sqlite3_db_filename(db, "main");
  char *set_user_version = NULL, *pass = NULL, *attach_command = NULL, *migrated_db_filename = NULL, *keyspec = NULL, *temp = NULL, *journal_mode = NULL, *set_journal_mode = NULL, *pragma_compat = NULL;
  Btree *pDest = NULL, *pSrc = NULL;
  sqlite3_file *srcfile, *destfile;
#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  LPWSTR w_db_filename = NULL, w_migrated_db_filename = NULL;
  int w_db_filename_sz = 0, w_migrated_db_filename_sz = 0;
#endif
  pass_sz = keyspec_sz = rc = user_version = 0;

  if(!db_filename || sqlite3Strlen30(db_filename) < 1) 
    goto cleanup; /* exit immediately if this is an in memory database */ 
  
  /* pull the provided password / key material off the current codec context */
  pass_sz = ctx->read_ctx->pass_sz;
  pass = sqlcipher_malloc(pass_sz+1);
  memset(pass, 0, pass_sz+1);
  memcpy(pass, ctx->read_ctx->pass, pass_sz);
                                            
  /* Version 4 - current, no upgrade required, so exit immediately */
  rc = sqlcipher_check_connection(db_filename, pass, pass_sz, "", &user_version, &journal_mode);
  if(rc == SQLITE_OK){
    CODEC_TRACE("No upgrade required - exiting\n");
    goto cleanup;
  }

  for(i = 3; i > 0; i--) {
    pragma_compat = sqlite3_mprintf("PRAGMA cipher_compatibility = %d;", i);
    rc = sqlcipher_check_connection(db_filename, pass, pass_sz, pragma_compat, &user_version, &journal_mode);
    if(rc == SQLITE_OK) {
      CODEC_TRACE("Version %d format found\n", i);
      goto migrate;
    }
    if(pragma_compat) sqlcipher_free(pragma_compat, sqlite3Strlen30(pragma_compat)); 
    pragma_compat = NULL;
  }
  /* if we exit the loop normally we failed to determine the version, this is an error */
  CODEC_TRACE("Upgrade format not determined\n");
  goto handle_error;

migrate:

  temp = sqlite3_mprintf("%s-migrated", db_filename);
  /* overallocate migrated_db_filename, because sqlite3OsOpen will read past the null terminator
   * to determine whether the filename was URI formatted */
  migrated_db_filename = sqlcipher_malloc(sqlite3Strlen30(temp)+2); 
  memcpy(migrated_db_filename, temp, sqlite3Strlen30(temp));
  sqlcipher_free(temp, sqlite3Strlen30(temp));

  attach_command = sqlite3_mprintf("ATTACH DATABASE '%s' as migrate;", migrated_db_filename, pass); 
  set_user_version = sqlite3_mprintf("PRAGMA migrate.user_version = %d;", user_version);

  rc = sqlite3_exec(db, pragma_compat, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    CODEC_TRACE("set compatibility mode failed, error code %d\n", rc);
    goto handle_error;
  }

  /* force journal mode to DELETE, we will set it back later if different */
  rc = sqlite3_exec(db, "PRAGMA journal_mode = delete;", NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    CODEC_TRACE("force journal mode DELETE failed, error code %d\n", rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, attach_command, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    CODEC_TRACE("attach failed, error code %d\n", rc);
    goto handle_error;
  }

  rc = sqlite3_key_v2(db, "migrate", pass, pass_sz);
  if(rc != SQLITE_OK){
    CODEC_TRACE("keying attached database failed, error code %d\n", rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, "SELECT sqlcipher_export('migrate');", NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    CODEC_TRACE("sqlcipher_export failed, error code %d\n", rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, set_user_version, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    CODEC_TRACE("set user version failed, error code %d\n", rc);
    goto handle_error;
  }

  if( !db->autoCommit ){
    CODEC_TRACE("cannot migrate from within a transaction");
    goto handle_error;
  }
  if( db->nVdbeActive>1 ){
    CODEC_TRACE("cannot migrate - SQL statements in progress");
    goto handle_error;
  }

  pDest = db->aDb[0].pBt;
  pDb = &(db->aDb[db->nDb-1]);
  pSrc = pDb->pBt;

  nRes = sqlite3BtreeGetRequestedReserve(pSrc);
  /* unset the BTS_PAGESIZE_FIXED flag to avoid SQLITE_READONLY */
  pDest->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED; 
  rc = sqlite3BtreeSetPageSize(pDest, default_page_size, nRes, 0);
  CODEC_TRACE("set btree page size to %d res %d rc %d\n", default_page_size, nRes, rc);
  if( rc!=SQLITE_OK ) goto handle_error;

  sqlite3CodecGetKey(db, db->nDb - 1, (void**)&keyspec, &keyspec_sz);
  sqlite3CodecAttach(db, 0, keyspec, keyspec_sz);
  
  srcfile = sqlite3PagerFile(pSrc->pBt->pPager);
  destfile = sqlite3PagerFile(pDest->pBt->pPager);

  sqlite3OsClose(srcfile);
  sqlite3OsClose(destfile); 

#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  CODEC_TRACE("performing windows MoveFileExA\n");

  w_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) db_filename, -1, NULL, 0);
  w_db_filename = sqlcipher_malloc(w_db_filename_sz * sizeof(wchar_t));
  w_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) db_filename, -1, (const LPWSTR) w_db_filename, w_db_filename_sz);

  w_migrated_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) migrated_db_filename, -1, NULL, 0);
  w_migrated_db_filename = sqlcipher_malloc(w_migrated_db_filename_sz * sizeof(wchar_t));
  w_migrated_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) migrated_db_filename, -1, (const LPWSTR) w_migrated_db_filename, w_migrated_db_filename_sz);

  if(!MoveFileExW(w_migrated_db_filename, w_db_filename, MOVEFILE_REPLACE_EXISTING)) {
    CODEC_TRACE("move error");
    rc = SQLITE_ERROR;
    CODEC_TRACE("error occurred while renaming %d\n", rc);
    goto handle_error;
  }
#else
  CODEC_TRACE("performing POSIX rename\n");
  if ((rc = rename(migrated_db_filename, db_filename)) != 0) {
    CODEC_TRACE("error occurred while renaming %d\n", rc);
    goto handle_error;
  }
#endif    
  CODEC_TRACE("renamed migration database %s to main database %s: %d\n", migrated_db_filename, db_filename, rc);

  rc = sqlite3OsOpen(db->pVfs, migrated_db_filename, srcfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags);
  CODEC_TRACE("reopened migration database: %d\n", rc);
  if( rc!=SQLITE_OK ) goto handle_error;

  rc = sqlite3OsOpen(db->pVfs, db_filename, destfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags);
  CODEC_TRACE("reopened main database: %d\n", rc);
  if( rc!=SQLITE_OK ) goto handle_error;

  sqlite3pager_reset(pDest->pBt->pPager);
  CODEC_TRACE("reset pager\n");

  rc = sqlite3_exec(db, "DETACH DATABASE migrate;", NULL, NULL, NULL);
  CODEC_TRACE("DETACH DATABASE called %d\n", rc);
  if(rc != SQLITE_OK) goto cleanup; 

  rc = sqlite3OsDelete(db->pVfs, migrated_db_filename, 0);
  CODEC_TRACE("deleted migration database: %d\n", rc);
  if( rc!=SQLITE_OK ) goto handle_error;

  sqlite3ResetAllSchemasOfConnection(db);
  CODEC_TRACE("reset all schemas\n");

  set_journal_mode = sqlite3_mprintf("PRAGMA journal_mode = %s;", journal_mode);
  rc = sqlite3_exec(db, set_journal_mode, NULL, NULL, NULL); 
  CODEC_TRACE("%s: %d\n", set_journal_mode, rc);
  if( rc!=SQLITE_OK ) goto handle_error;

  goto cleanup;

handle_error:
  CODEC_TRACE("An error occurred attempting to migrate the database - last error %d\n", rc);
  rc = SQLITE_ERROR;

cleanup:
  if(pass) sqlcipher_free(pass, pass_sz);
  if(attach_command) sqlcipher_free(attach_command, sqlite3Strlen30(attach_command)); 
  if(migrated_db_filename) sqlcipher_free(migrated_db_filename, sqlite3Strlen30(migrated_db_filename)); 
  if(set_user_version) sqlcipher_free(set_user_version, sqlite3Strlen30(set_user_version)); 
  if(set_journal_mode) sqlcipher_free(set_journal_mode, sqlite3Strlen30(set_journal_mode)); 
  if(journal_mode) sqlcipher_free(journal_mode, sqlite3Strlen30(journal_mode)); 
  if(pragma_compat) sqlcipher_free(pragma_compat, sqlite3Strlen30(pragma_compat)); 
#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  if(w_db_filename) sqlcipher_free(w_db_filename, w_db_filename_sz);
  if(w_migrated_db_filename) sqlcipher_free(w_migrated_db_filename, w_migrated_db_filename_sz);
#endif
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

#if !defined(SQLITE_OMIT_TRACE) && !defined(SQLITE_OMIT_DEPRECATED)
static void sqlcipher_profile_callback(void *file, const char *sql, sqlite3_uint64 run_time){
  FILE *f = (FILE*)file;
  double elapsed = run_time/1000000.0;
  if(f) fprintf(f, "Elapsed time:%.3f ms - %s\n", elapsed, sql);
}
#endif

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
#if !defined(SQLCIPHER_PROFILE_USE_FOPEN) && (defined(_WIN32) && (__STDC_VERSION__ > 199901L) || defined(SQLITE_OS_WINRT))
    if(fopen_s(&f, destination, "a") != 0) return SQLITE_ERROR;
#else
    if((f = fopen(destination, "a")) == 0) return SQLITE_ERROR;
#endif    
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

#endif
/* END SQLCIPHER */
