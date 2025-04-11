/* 
** SQLCipher
** http://zetetic.net
** 
** Copyright (c) 2008-2024, ZETETIC LLC
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

#include "sqliteInt.h"
#include "btreeInt.h"
#include "pager.h"
#include "vdbeInt.h"

#if !defined(SQLCIPHER_OMIT_LOG_DEVICE)
#if defined(__ANDROID__)
#include <android/log.h>
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#include <os/log.h>
#endif
#endif

#include <time.h>

#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
#include <windows.h> /*  amalgamator: dontcache */
#else
#include <sys/time.h> /* amalgamator: dontcache */
#endif

#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__) || defined(_AIX)
#include <errno.h> /* amalgamator: dontcache */
#include <unistd.h> /* amalgamator: dontcache */
#include <sys/resource.h> /* amalgamator: dontcache */
#include <sys/mman.h> /* amalgamator: dontcache */
#endif
#endif

#include <assert.h>
#include "sqlcipher.h"

#if !defined(SQLITE_EXTRA_INIT) || !defined(SQLITE_EXTRA_SHUTDOWN)
#error "SQLCipher must be compiled with -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown"
#endif

#if !defined(SQLITE_THREADSAFE) || !(SQLITE_THREADSAFE == 1 || SQLITE_THREADSAFE == 2)
#error "SQLCipher must be compiled with -DSQLITE_THREADSAFE=<1 or 2>"
#endif

#if !defined(SQLITE_TEMP_STORE) || SQLITE_TEMP_STORE == 0 || SQLITE_TEMP_STORE == 1
#error "SQLCipher must be compiled with -DSQLITE_TEMP_STORE=<2 or 3>"
#endif

/* extensions defined in pager.c */ 
void *sqlcipherPagerGetCodec(Pager*);
void sqlcipherPagerSetCodec(Pager*, void *(*)(void*,void*,Pgno,int),  void (*)(void*,int,int),  void (*)(void*), void *);
int sqlite3pager_is_sj_pgno(Pager*, Pgno);
void sqlite3pager_error(Pager*, int);
void sqlite3pager_reset(Pager *pPager);
/* end extensions defined in pager.c */

#if !defined (SQLCIPHER_CRYPTO_CC) \
   && !defined (SQLCIPHER_CRYPTO_LIBTOMCRYPT) \
   && !defined (SQLCIPHER_CRYPTO_NSS) \
   && !defined (SQLCIPHER_CRYPTO_OPENSSL) \
   && !defined (SQLCIPHER_CRYPTO_CUSTOM)
#define SQLCIPHER_CRYPTO_OPENSSL
#endif

#define FILE_HEADER_SZ 16

#define CIPHER_XSTR(s) CIPHER_STR(s)
#define CIPHER_STR(s) #s

#ifndef CIPHER_VERSION_NUMBER
#define CIPHER_VERSION_NUMBER 4.8.0
#endif

#ifndef CIPHER_VERSION_BUILD
#define CIPHER_VERSION_BUILD community
#endif

#define CIPHER_DECRYPT 0
#define CIPHER_ENCRYPT 1

#define CIPHER_READ_CTX 0
#define CIPHER_WRITE_CTX 1
#define CIPHER_READWRITE_CTX 2

#ifndef PBKDF2_ITER
#define PBKDF2_ITER 256000
#endif

#define SQLCIPHER_FLAG_GET(FLAG,BIT) ((FLAG & BIT) != 0)
#define SQLCIPHER_FLAG_SET(FLAG,BIT) FLAG |= BIT
#define SQLCIPHER_FLAG_UNSET(FLAG,BIT) FLAG &= ~BIT

/* possible flags for codec_ctx->flags */
#define CIPHER_FLAG_HMAC          (1 << 0)
#define CIPHER_FLAG_LE_PGNO       (1 << 1)
#define CIPHER_FLAG_BE_PGNO       (1 << 2)
#define CIPHER_FLAG_KEY_USED      (1 << 3)
#define CIPHER_FLAG_HAS_KDF_SALT  (1 << 4)


#ifndef DEFAULT_CIPHER_FLAGS
#define DEFAULT_CIPHER_FLAGS CIPHER_FLAG_HMAC | CIPHER_FLAG_LE_PGNO
#endif


/* by default, sqlcipher will use a reduced number of iterations to generate
   the HMAC key / or transform a raw cipher key 
   */
#ifndef FAST_PBKDF2_ITER
#define FAST_PBKDF2_ITER 2
#endif

/* this if a fixed random array that will be xor'd with the database salt to ensure that the
   salt passed to the HMAC key derivation function is not the same as that used to derive
   the encryption key. This can be overridden at compile time but it will make the resulting
   binary incompatible with the default builds when using HMAC. A future version of SQLcipher
   will likely allow this to be defined at runtime via pragma */ 
#ifndef HMAC_SALT_MASK
#define HMAC_SALT_MASK 0x3a
#endif

#ifndef CIPHER_MAX_IV_SZ
#define CIPHER_MAX_IV_SZ 16
#endif

#ifndef CIPHER_MAX_KEY_SZ
#define CIPHER_MAX_KEY_SZ 64
#endif


/* the default implementation of SQLCipher uses a cipher_ctx
   to keep track of read / write state separately. The following
   struct and associated functions are defined here */
typedef struct {
  int derive_key;
  int pass_sz;
  unsigned char *key;
  unsigned char *hmac_key;
  unsigned char *pass;
} cipher_ctx;


typedef struct {
  int store_pass;
  int kdf_iter;
  int fast_kdf_iter;
  int kdf_salt_sz;
  int key_sz;
  int iv_sz;
  int block_sz;
  int page_sz;
  int reserve_sz;
  int hmac_sz;
  int plaintext_header_sz;
  int hmac_algorithm;
  int kdf_algorithm;
  int error;
  unsigned int flags;
  unsigned char *kdf_salt;
  unsigned char *hmac_kdf_salt;
  unsigned char *buffer;
  Btree *pBt;
  cipher_ctx *read_ctx;
  cipher_ctx *write_ctx;
  sqlcipher_provider *provider;
  void *provider_ctx;
} codec_ctx ;

typedef struct private_block private_block;
struct private_block {
  private_block *next;
  u32 size;
  u32 is_used;
};

/* implementation of simple, fast PSRNG function using xoshiro256++ (XOR/shift/rotate)
 * https://prng.di.unimi.it/ under the public domain via https://prng.di.unimi.it/xoshiro256plusplus.c
 * xoshiro is NEVER used for any cryptographic functions as CSPRNG. It is solely used for
 * generating random data for testing, debugging, and forensic purposes (overwriting memory segments) */
static volatile uint64_t xoshiro_s[4];

static inline uint64_t xoshiro_rotl(const uint64_t x, int k) {
  return (x << k) | (x >> (64 - k));
}

uint64_t xoshiro_next(void) {
  volatile uint64_t result = xoshiro_rotl(xoshiro_s[0] + xoshiro_s[3], 23) + xoshiro_s[0];
  volatile uint64_t t = xoshiro_s[1] << 17;

  xoshiro_s[2] ^= xoshiro_s[0];
  xoshiro_s[3] ^= xoshiro_s[1];
  xoshiro_s[1] ^= xoshiro_s[2];
  xoshiro_s[0] ^= xoshiro_s[3];

  xoshiro_s[2] ^= t;

  xoshiro_s[3] = xoshiro_rotl(xoshiro_s[3], 45);

  return result;
}

static void xoshiro_randomness(unsigned char *ptr, int sz) {
  volatile uint64_t val;
  volatile int to_copy;
  while (sz > 0) {
    val = xoshiro_next();
    to_copy = (sz >= sizeof(val)) ? sizeof(val) : sz;
    memcpy(ptr, (void *) &val, to_copy);
    ptr += to_copy;
    sz -= to_copy;
  }
}

#ifdef SQLCIPHER_TEST
/* possible flags for simulating specific test conditions */
#define TEST_FAIL_ENCRYPT 0x01
#define TEST_FAIL_DECRYPT 0x02
#define TEST_FAIL_MIGRATE 0x04

static volatile unsigned int cipher_test_flags = 0;
static volatile int cipher_test_rand = 0;

static int sqlcipher_get_test_fail() {
  int x;

  /* if cipher_test_rand is not set to a non-zero value always fail (return true) */
  if (cipher_test_rand == 0) return 1;

  xoshiro_randomness((unsigned char *) &x, sizeof(x));
  return ((x % cipher_test_rand) == 0);
}
#endif

static volatile unsigned int default_flags = DEFAULT_CIPHER_FLAGS;
static volatile unsigned char hmac_salt_mask = HMAC_SALT_MASK;
static volatile int default_kdf_iter = PBKDF2_ITER;
static volatile int default_page_size = 4096;
static volatile int default_plaintext_header_size = 0;
static volatile int default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
static volatile int default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
static volatile int sqlcipher_mem_security_on = 0;
static volatile int sqlcipher_mem_executed = 0;
static volatile int sqlcipher_mem_initialized = 0;
static volatile sqlite3_mem_methods default_mem_methods;
static sqlcipher_provider *default_provider = NULL;

static sqlite3_mutex* sqlcipher_static_mutex[SQLCIPHER_MUTEX_COUNT];
static FILE* sqlcipher_log_file = NULL;
static volatile int sqlcipher_log_device = 0;
static volatile unsigned int sqlcipher_log_level = SQLCIPHER_LOG_NONE;
static volatile unsigned int sqlcipher_log_source = SQLCIPHER_LOG_ANY;
static volatile int sqlcipher_log_set = 0;

static size_t sqlcipher_shield_mask_sz  = 32;
static u8* sqlcipher_shield_mask = NULL;

/* Establish the default size of the private heap. This can be overriden 
 * at compile time by setting -DSQLCIPHER_PRIVATE_HEAP_SIZE_DEFAULT=X */
#ifndef SQLCIPHER_PRIVATE_HEAP_SIZE_DEFAULT
/* On android, the maximim amount of memory that can be memlocked in 64k. This also
 * seems to be a popular ulimit on linux distributions, containsers, etc. Therefore
 * the default heap size is chosen as 48K, which is either 4 (with 4k page size)
 * or 1 (with 16k page size) page less than the max. We choose to allocate slightly
 * less than the max just in case the app has locked some other page(s). This
 * initial allocation should be enough to support at least 10 concurrent
 * sqlcipher-enabled database connections at the same time without requiring any
 * overflow allocations */
#define SQLCIPHER_PRIVATE_HEAP_SIZE_DEFAULT 49152
#endif
/* if default allocation fails, we'll reduce the size by this amount
 * and try again. This is also the minimium of the private heap. The minimum
 * size will be 4 4K pages or 1 16K page (possible with latest android)*/
#define SQLCIPHER_PRIVATE_HEAP_SIZE_STEP 16384

static volatile size_t private_heap_sz = SQLCIPHER_PRIVATE_HEAP_SIZE_DEFAULT;
static u8* private_heap = NULL;

/* to prevent excessive fragmentation blocks will
 * only be split if there are at least this many
 * bytes available after the split. This should allow for at
 * least two addtional small allocations */
#define SQLCIPHER_PRIVATE_HEAP_MIN_SPLIT_SIZE 32

/* requested sizes will be rounded up to the nearest 8 bytes for alignment */
#define SQLCIPHER_PRIVATE_HEAP_ALIGNMENT 8
#define SQLCIPHER_PRIVATE_HEAP_ROUNDUP(x) ((x % SQLCIPHER_PRIVATE_HEAP_ALIGNMENT) ? \
  ((x / SQLCIPHER_PRIVATE_HEAP_ALIGNMENT) + 1) * SQLCIPHER_PRIVATE_HEAP_ALIGNMENT : x)

static volatile int sqlcipher_init = 0;
static volatile int sqlcipher_shutdown = 0;
static volatile int sqlcipher_cleanup = 0;
static int sqlcipher_init_error = SQLITE_ERROR;

static void sqlcipher_internal_free(void *, sqlite_uint64);
static void *sqlcipher_internal_malloc(sqlite_uint64);


/*
**  Simple shared routines for converting hex char strings to binary data
 */
static int cipher_hex2int(char c) {
  return (c>='0' && c<='9') ? (c)-'0' :
         (c>='A' && c<='F') ? (c)-'A'+10 :
         (c>='a' && c<='f') ? (c)-'a'+10 : 0;
}

static void cipher_hex2bin(const unsigned char *hex, int sz, unsigned char *out){
  int i;
  for(i = 0; i < sz; i += 2){
    out[i/2] = (cipher_hex2int(hex[i])<<4) | cipher_hex2int(hex[i+1]);
  }
}

static void cipher_bin2hex(const unsigned char* in, int sz, char *out) {
    int i;
    for(i=0; i < sz; i++) {
      sqlite3_snprintf(3, out + (i*2), "%02x ", in[i]);
    } 
}

static int cipher_isHex(const unsigned char *hex, int sz){
  int i;
  for(i = 0; i < sz; i++) {
    unsigned char c = hex[i];
    if ((c < '0' || c > '9') &&
        (c < 'A' || c > 'F') &&
        (c < 'a' || c > 'f')) {
      return 0;
    }
  }
  return 1;
}

sqlite3_mutex* sqlcipher_mutex(int mutex) {
  if(mutex < 0 || mutex >= SQLCIPHER_MUTEX_COUNT) return NULL;
  return sqlcipher_static_mutex[mutex];
}

static void sqlcipher_atexit(void) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipher_extra_shutdown()\n", __func__);
  sqlcipher_extra_shutdown();
}

static void sqlcipher_fini(void) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipher_extra_shutdown()\n", __func__);
  sqlcipher_extra_shutdown();
}

#if defined(_WIN32)
#ifndef SQLCIPHER_OMIT_DLLMAIN
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_DETACH:
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipher_extra_shutdown()\n", __func__);
      sqlcipher_extra_shutdown();
      break;
    default:
      break;
  }
  return TRUE;
}
#endif
#elif defined(__APPLE__)
static void (*const sqlcipher_fini_func)(void) __attribute__((used, section("__DATA,__mod_term_func"))) = sqlcipher_fini;
#else
static void (*const sqlcipher_fini_func)(void) __attribute__((used, section(".fini_array"))) = sqlcipher_fini;
#endif

static void sqlcipher_exportFunc(sqlite3_context*, int, sqlite3_value**);

static int sqlcipher_export_init(sqlite3* db, const char** errmsg, const struct sqlite3_api_routines* api) { 
  sqlite3_create_function_v2(db, "sqlcipher_export", -1, SQLITE_TEXT, 0, sqlcipher_exportFunc, 0, 0, 0);
  return SQLITE_OK;
}

/* The extra_init function is called by sqlite3_init automaticay by virtue of
 * being defined with SQLITE_EXTRA_INIT. This function sets up 
 * static mutexes used internally by SQLCipher and initializes
 * the internal private heap */
int sqlcipher_extra_init(const char* arg) {
  int rc = SQLITE_OK, i=0;
  void* provider_ctx = NULL;

  sqlite3_mutex_enter(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));

  if(sqlcipher_init) {
    /* if this init routine already completed successfully return immediately */
    sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
    return SQLITE_OK;
  }

  /* only register cleanup handlers once per process */
  if(!sqlcipher_cleanup) {
    atexit(sqlcipher_atexit);
    sqlcipher_cleanup = 1;
  }

#ifndef SQLCIPHER_OMIT_DEFAULT_LOGGING
  /* when sqlcipher is first activated, set a default log target and level of WARN if the
     logging settings have not yet been initialized. Use the "device log" for 
     android (logcat) or apple (console). Use stderr on all other platforms. */  
  if(!sqlcipher_log_set) {

    /* set log level if it is different than the uninitalized default value of NONE */ 
    if(sqlcipher_log_level == SQLCIPHER_LOG_NONE) {
      sqlcipher_log_level = SQLCIPHER_LOG_WARN;
    }

    /* set the default file or device if neither is already set */
    if(sqlcipher_log_device == 0 && sqlcipher_log_file == NULL) {
#if defined(__ANDROID__) || defined(__APPLE__)
      sqlcipher_log_device = 1;
#else
      sqlcipher_log_file = stderr;
#endif
    }
    sqlcipher_log_set = 1;
  }
#endif

  /* allocate static mutexe, and return error if any fail to allocate */
  for(i = 0; i < SQLCIPHER_MUTEX_COUNT; i++) {
    if(sqlcipher_static_mutex[i] == NULL) {
      if((sqlcipher_static_mutex[i] = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST)) == NULL) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate static mutex %d", __func__, i);
        rc = SQLITE_NOMEM; 
        goto error;
      }
    }
  }

  /* initialize the private heap for use in internal SQLCipher memory allocations */
  if(private_heap == NULL) {
    while(private_heap_sz >= SQLCIPHER_PRIVATE_HEAP_SIZE_STEP) {
      /* attempt to allocate the private heap. If allocation fails, reduce the size and try again */
      if((private_heap = sqlcipher_internal_malloc(private_heap_sz))) {
        xoshiro_randomness(private_heap, private_heap_sz);
        /* initialize the head block of the linked list at the start of the heap */ 
        private_block *head = (private_block *) private_heap; 
        head->is_used = 0;
        head->size = private_heap_sz - sizeof(private_block);
        head->next = NULL;
        break;
      }

      /* allocation failed, reduce the requested size of the heap */
      private_heap_sz -= SQLCIPHER_PRIVATE_HEAP_SIZE_STEP;
    }
  }
  if(!private_heap) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate private heap", __func__); 
    rc = SQLITE_NOMEM; 
    goto error;
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
#elif defined (SQLCIPHER_CRYPTO_OSSL3)
    extern int sqlcipher_ossl3_setup(sqlcipher_provider *p);
    sqlcipher_ossl3_setup(p);
#elif defined (SQLCIPHER_CRYPTO_CUSTOM)
    extern int SQLCIPHER_CRYPTO_CUSTOM(sqlcipher_provider *p);
    SQLCIPHER_CRYPTO_CUSTOM(p);
#else
#error "NO DEFAULT SQLCIPHER CRYPTO PROVIDER DEFINED"
#endif
    if((rc = sqlcipher_register_provider(p)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register provider %p %d", __func__, p, rc); 
      goto error;
    }
  }

  /* required random data */
  if((rc = default_provider->ctx_init(&provider_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to initilize provider context %d", __func__, rc);
    goto error; 
  }

  if((rc = default_provider->random(provider_ctx, (void *)xoshiro_s, sizeof(xoshiro_s))) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to generate xoshiro seed %d", __func__, rc); 
    goto error; 
  }

  if(!sqlcipher_shield_mask) {
    if(!(sqlcipher_shield_mask = sqlcipher_internal_malloc(sqlcipher_shield_mask_sz))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate shield mask", __func__); 
      goto error; 
    }
    if((rc = default_provider->random(provider_ctx, sqlcipher_shield_mask, sqlcipher_shield_mask_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to generate requisite random mask data %d", __func__, rc); 
      goto error; 
    }
  }

  default_provider->ctx_free(provider_ctx);

  sqlcipher_init = 1;
  sqlcipher_shutdown = 0;

  /* leave the master mutex so we can proceed with auto extension registration */
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));

  /* finally, extension registration occurs outside of the mutex because it is
   * uses SQLITE_MUTEX_STATIC_MASTER itself */
  sqlite3_auto_extension((void (*)(void))sqlcipher_export_init);

  return SQLITE_OK;
 
error:
  /* if an error occurs during initialization, tear down everything that was setup */
  if(private_heap) {
    sqlcipher_internal_free(private_heap, private_heap_sz);
    private_heap = NULL;
  }
  if(sqlcipher_shield_mask) {
    sqlcipher_internal_free(sqlcipher_shield_mask, sqlcipher_shield_mask_sz);
    sqlcipher_shield_mask = NULL;
  }
  for(i = 0; i < SQLCIPHER_MUTEX_COUNT; i++) {
    if(sqlcipher_static_mutex[i]) {
      sqlite3_mutex_free(sqlcipher_static_mutex[i]);
      sqlcipher_static_mutex[i] = NULL;
    }
  }

  /* post cleanup return the error code back up to sqlite3_init() */
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  sqlcipher_init_error = rc;
  return rc;
}

/* The extra_shutdown function is called by sqlite3_shutdown()
 * because it is defined with SQLITE_EXTRA_SHUTDOWN. In addition it will
 * be called via atexit(), finalizer, and DllMain. The function will
 * cleanup resources allocated by SQLCipher including mutexes,
 * the private heap, and default provider. */
void sqlcipher_extra_shutdown(void) {
  int i = 0;
  sqlcipher_provider *provider = NULL;
  sqlite3_mutex *mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER); 
  if(mutex) {
    sqlite3_mutex_enter(mutex);
  }

  /* if sqlcipher hasn't been initialized or the shutdown already completed exit early */
  if(!sqlcipher_init || sqlcipher_shutdown) {
    goto cleanup;
  }

  if(sqlcipher_shield_mask) {
    sqlcipher_internal_free(sqlcipher_shield_mask, sqlcipher_shield_mask_sz);
    sqlcipher_shield_mask = NULL;
  }

  /* free the provider list. start at the default provider and move through the list
   * freeing each one. If a provider has a shutdown function, call it before freeing.
   * finally NULL out the default_provider */
  provider = default_provider;
  while(provider) {
    sqlcipher_provider *next = provider->next;
    if(provider->shutdown) {
      provider->shutdown();
    }
    sqlcipher_free(provider, sizeof(sqlcipher_provider));
    provider = next;
  }
  default_provider = NULL;

  /* free private heap. If SQLCipher is compiled in test mode, it will deliberately
     not free the heap (leaking it) if the heap is not empty. This will allow tooling
     to detect memory issues like unfreed private heap memory */
  if(private_heap) {
#ifdef SQLCIPHER_TEST
    size_t used = 0;
    private_block *block = NULL;
    block = (private_block *) private_heap;
    while (block != NULL) {
      if(block->is_used) {
        used+= block->size;
        i++;
      }
      block = block->next;
    }
    if(used > 0) {
      /* don't free the heap so that sqlite treats this as unfreed memory */ 
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, 
        "%s: SQLCipher private heap unfreed memory %u bytes in %d allocations\n", __func__, used, i);
    } else {
      sqlcipher_internal_free(private_heap, private_heap_sz);
      private_heap = NULL;
    }
#else
    sqlcipher_internal_free(private_heap, private_heap_sz);
    private_heap = NULL;
#endif
  }

  /* free all of sqlcipher's static mutexes */
  for(i = 0; i < SQLCIPHER_MUTEX_COUNT; i++) {
    if(sqlcipher_static_mutex[i]) {
      sqlite3_mutex_free(sqlcipher_static_mutex[i]);
      sqlcipher_static_mutex[i] = NULL;
    }
  }

cleanup: 
  sqlcipher_init = 0;
  sqlcipher_init_error = SQLITE_ERROR;
  sqlcipher_shutdown = 1;
  if(mutex) {
    sqlite3_mutex_leave(mutex);
  }
}

static void sqlcipher_shield(unsigned char *in, int sz) {
  int i = 0;
  for(i = 0; i < sz; i++) {
    in[i] ^= sqlcipher_shield_mask[i % sqlcipher_shield_mask_sz];
  }
}

/* constant time memset using volitile to avoid having the memset
   optimized out by the compiler. 
   Note: As suggested by Joachim Schipper (joachim.schipper@fox-it.com)
*/
void* sqlcipher_memset(void *v, unsigned char value, sqlite_uint64 len) {
  volatile sqlite_uint64 i = 0;
  volatile unsigned char *a = v;

  if (v == NULL) return v;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_memset: setting %p[0-%llu]=%d)", a, len, value);
  for(i = 0; i < len; i++) {
    a[i] = value;
  }

  return v;
}

/* constant time memory check tests every position of a memory segement
   matches a single value (i.e. the memory is all zeros)
   returns 0 if match, 1 of no match */
int sqlcipher_ismemset(const void *v, unsigned char value, sqlite_uint64 len) {
  const volatile unsigned char *a = v;
  volatile sqlite_uint64 i = 0, result = 0;

  for(i = 0; i < len; i++) {
    result |= a[i] ^ value;
  }

  return (result != 0);
}

/* constant time memory comparison routine. 
   returns 0 if match, 1 if no match */
int sqlcipher_memcmp(const void *v0, const void *v1, int len) {
  const volatile unsigned char *a0 = v0, *a1 = v1;
  volatile int i = 0, result = 0;

  for(i = 0; i < len; i++) {
    result |= a0[i] ^ a1[i];
  }
  
  return (result != 0);
}

static void sqlcipher_mlock(void *ptr, sqlite_uint64 sz) {
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__)
  int rc;
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  unsigned long offset = (unsigned long) ptr % pagesize;

  if(ptr == NULL || sz == 0) return;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_mlock: calling mlock(%p,%lu); _SC_PAGESIZE=%lu", ptr - offset, sz + offset, pagesize);
  rc = mlock(ptr - offset, sz + offset);
  if(rc!=0) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_MEMORY, "sqlcipher_mlock: mlock() returned %d errno=%d", rc, errno);
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "sqlcipher_mlock: mlock(%p,%lu) returned %d errno=%d", ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_PC_APP))
  int rc;
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_mlock: calling VirtualLock(%p,%d)", ptr, sz);
  rc = VirtualLock(ptr, sz);
  if(rc==0) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_MEMORY, "sqlcipher_mlock: VirtualLock() returned %d LastError=%d", rc, GetLastError());
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "sqlcipher_mlock: VirtualLock(%p,%d) returned %d LastError=%d", ptr, sz, rc, GetLastError());
  }
#endif
#endif
#endif
}

static void sqlcipher_munlock(void *ptr, sqlite_uint64 sz) {
#ifndef OMIT_MEMLOCK
#if defined(__unix__) || defined(__APPLE__)
  int rc;
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  unsigned long offset = (unsigned long) ptr % pagesize;

  if(ptr == NULL || sz == 0) return;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_munlock: calling munlock(%p,%lu)", ptr - offset, sz + offset);
  rc = munlock(ptr - offset, sz + offset);
  if(rc!=0) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "sqlcipher_munlock: munlock(%p,%lu) returned %d errno=%d", ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_PC_APP))
  int rc;

  if(ptr == NULL || sz == 0) return;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_munlock: calling VirtualUnlock(%p,%d)", ptr, sz);
  rc = VirtualUnlock(ptr, sz);

  /* because memory allocations may be made from the same individual page, it is possible for VirtualUnlock to be called
   * multiple times for the same page. Subsequent calls will return an error, but this can be safely ignored (i.e. because
   * the previous call for that page unlocked the memory already). Log an info level event only in that case. */
  if(!rc) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "sqlcipher_munlock: VirtualUnlock(%p,%d) returned %d LastError=%d", ptr, sz, rc, GetLastError());
  }
#endif
#endif
#endif
}

/** sqlcipher wraps the default memory subsystem so it can optionally provide the
  * memory security feature which will lock and sanitize ALL memory used by 
  * the sqlite library internally. Memory security feature is disabled by default
  * but but the wrapper is used regardless, it just forwards to the default
  * memory management implementation when disabled
  */
static int sqlcipher_mem_init(void *pAppData) {
  return default_mem_methods.xInit(pAppData);
}
static void sqlcipher_mem_shutdown(void *pAppData) {
  default_mem_methods.xShutdown(pAppData);
}
static void *sqlcipher_mem_malloc(int n) {
  void *ptr = default_mem_methods.xMalloc(n);
  if(!sqlcipher_mem_executed) sqlcipher_mem_executed = 1;
  if(sqlcipher_mem_security_on) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_mem_malloc: calling sqlcipher_mlock(%p,%d)", ptr, n);
    sqlcipher_mlock(ptr, n); 
  }
  return ptr;
}
static int sqlcipher_mem_size(void *p) {
  return default_mem_methods.xSize(p);
}
static void sqlcipher_mem_free(void *p) {
  int sz;
  if(!sqlcipher_mem_executed) sqlcipher_mem_executed = 1;
  if(sqlcipher_mem_security_on) {
    sz = sqlcipher_mem_size(p);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: calling xoshiro_randomness(%p,%d) and sqlcipher_munlock(%p, %d)", __func__, p, sz, p, sz);
    xoshiro_randomness(p, sz);
    sqlcipher_munlock(p, sz);
  }
  default_mem_methods.xFree(p);
}
static void *sqlcipher_mem_realloc(void *p, int n) {
  void *new = NULL;
  int orig_sz = 0;
  if(sqlcipher_mem_security_on) {
    orig_sz = sqlcipher_mem_size(p);
    if (n==0) {
      sqlcipher_mem_free(p);
      return NULL;
    } else if (!p) {
      return sqlcipher_mem_malloc(n);
    } else if(n <= orig_sz) {
      return p;
    } else {
      new = sqlcipher_mem_malloc(n);
      if(new) {
        memcpy(new, p, orig_sz);
        sqlcipher_mem_free(p);
      }
      return new;
    }
  } else {
    return default_mem_methods.xRealloc(p, n);
  }
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
  if(sqlcipher_mem_initialized) return;
  if(sqlite3_config(SQLITE_CONFIG_GETMALLOC, &default_mem_methods) != SQLITE_OK ||
     sqlite3_config(SQLITE_CONFIG_MALLOC, &sqlcipher_mem_methods)  != SQLITE_OK) {
     sqlcipher_mem_security_on = sqlcipher_mem_executed = sqlcipher_mem_initialized = 0;
  } else {
#if !defined(OMIT_MEMLOCK) && defined(_WIN32) && !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_PC_APP))
    HANDLE process = NULL;
    SYSTEM_INFO info;
    SIZE_T dflt_min_size, dflt_max_size, min_size, max_size;
    DWORD pid = GetCurrentProcessId();

    if(pid == 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: error calling GetCurrentProcessId: %d", GetLastError());
      goto cleanup;
    }

    if((process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, FALSE, pid)) == NULL) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: error calling OpenProcess for pid=%d: %d", pid, GetLastError());
      goto cleanup;
    }

    /* lookup native memory page size for caclulating default working set sizes */
    GetNativeSystemInfo(&info);

    /* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsize#parameters
       Default Min Set Size is 50 pages. 
       Default Max Set Size is 345 pages */ 
    dflt_min_size = info.dwPageSize * 50; 
    dflt_max_size = info.dwPageSize * 345;
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: calculated dflt_min_size=%u dflt_max_size=%u for memory page size %d", dflt_min_size, dflt_max_size, info.dwPageSize);

    /* retrieve current min and max set sizes for comparison */
    if(!GetProcessWorkingSetSize(process, &min_size, &max_size)) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: error calling GetProcessWorkingSetSize %d",  GetLastError());
      goto cleanup;
    }
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: GetProcessWorkingSetSize returned min=%u max=%u", min_size, max_size);

    if(min_size == dflt_min_size && max_size == dflt_max_size) {
      /* application has not set any special non-default working set sizes. Caclulate the new min working set size to be 
         5 times default to allow greater number of pages to be VirtualLocked, max size will be left unchanged */ 
      min_size *= 5;
      if(!SetProcessWorkingSetSize(process, min_size, max_size)) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: error calling SetProcessWorkingSetSize with min=%u max=%u: %d", min_size, max_size, GetLastError());
        goto cleanup;
      }
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: called SetProcessWorkingSetSize for min=%u max=%u", min_size, max_size);
    } else {
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "sqlcipher_init_memmethods: application has custom working set sizes min=%u max=%u - skipped alteration of working set sizes", min_size, max_size);
    }

cleanup:
    if (process) CloseHandle(process);
#endif
    sqlcipher_mem_initialized = 1;
  }
}

/**
  * Free and wipe memory. Uses SQLites internal sqlite3_free so that memory
  * can be countend and memory leak detection works in the test suite. 
  * If ptr is not null memory will be freed. 
  * If sz is greater than zero, the memory will be overwritten with zero before it is freed
  * If sz is > 0, and not compiled with OMIT_MEMLOCK, system will attempt to unlock the
  * memory segment so it can be paged
  */
static void sqlcipher_internal_free(void *ptr, sqlite_uint64 sz) {
  xoshiro_randomness(ptr, sz);
  sqlcipher_munlock(ptr, sz);
  sqlite3_free(ptr);
}

/**
  * allocate memory. Uses sqlite's internall malloc wrapper so memory can be 
  * reference counted and leak detection works. Unless compiled with OMIT_MEMLOCK
  * attempts to lock the memory pages so sensitive information won't be swapped
  */
static void* sqlcipher_internal_malloc(sqlite_uint64 sz) {
  void *ptr;
  ptr = sqlite3_malloc(sz);
  sqlcipher_memset(ptr, 0, sz);
  sqlcipher_mlock(ptr, sz);
  return ptr;
}

void *sqlcipher_malloc(sqlite3_uint64 size) {
  void *alloc = NULL;
  private_block *block = NULL, *split = NULL;

  if(size < 1) return NULL;

  size = SQLCIPHER_PRIVATE_HEAP_ROUNDUP(size);

  block = (private_block *) private_heap;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_MEM", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_MEM));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_MEM", __func__);

    /* iterate through the blocks in the heap to find one which is big enough to hold
       the requested allocation. Stop when one is found. */
  while(block != NULL && alloc == NULL) {
    if(!block->is_used && block->size >= size) {
      /* mark the block as in use and set the return pointer to the start
         of the block free space */
      block->is_used = 1;
      alloc = ((u8*)block) + sizeof(private_block);
      sqlcipher_memset(alloc, 0, size);

      /* if there is at least the minimim amount of required space left after allocation, 
         split off a new free block  and insert it after the in-use block */ 
      if(block->size >= size + sizeof(private_block) + SQLCIPHER_PRIVATE_HEAP_MIN_SPLIT_SIZE) {
        split = (private_block*) (((u8*) block) + size + sizeof(private_block));
        split->is_used = 0;
        split->size = block->size - size - sizeof(private_block);

        /* insert inbetween current block and next */
        split->next = block->next;
        block->next = split;
        
        /* only set the size of the current block to the requested amount 
           if the block was split. otherwise, size will be the full amount
           of the block, which will actually be larger than the requested amount */
        block->size = size;
      } 
    }
    block = block->next;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_MEM", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_MEM));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_MEM", __func__);

  /* If we were unable to locate a free block large enough to service the request, the fallback
     behavior will simply attempt to allocate additional memory using malloc. */
  if(alloc == NULL) {
    alloc = sqlcipher_internal_malloc(size);
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: unable to allocate %llu bytes on private heap, allocated %p using sqlcipher_internal_malloc fallback", __func__, size, alloc);
  } else {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s allocated %llu bytes on private heap at %p", __func__, size, alloc);
  }

  return alloc;
}

void sqlcipher_free(void *mem, sqlite3_uint64 sz) {
  private_block *block = NULL, *prev = NULL;
  void *alloc = NULL;
  block = (private_block *) private_heap;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_MEM", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_MEM));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_MEM", __func__);

  /* search the heap for the block that contains this address */
  while(block != NULL) {
    alloc = ((u8*)block)+sizeof(private_block);
    /* if the memory address to be freed corresponds to this block's
       allocation, mark it as unused. If they don't match, move
       on to the next block */
    if(mem == alloc) {
      block->is_used = 0;
      xoshiro_randomness(alloc, block->size);

      /* check whether the previous block is free, if so merge*/
      if(prev && !prev->is_used) {
        prev->size = prev->size + sizeof(private_block) + block->size;
        prev->next = block->next;
        block = prev;
      }

      /* check to see whether the next block is free, if so merge */
      if(block->next && !block->next->is_used) {
        block->size = block->size + sizeof(private_block) + block->next->size;
        block->next = block->next->next;
      }

      /* once the block has been identified, marked free, and optionally
         consolidated with it's neighbors, exit the loop, but leave
         the block pointer intact so we know we found it in the heap */
      break;
    }

    prev = block;
    block = block->next;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_MEM", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_MEM));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_MEM", __func__);

  /* If the memory address couldn't be found in the private heap
     then it was allocated by the fallback mechanism and should
     be deallocated with free() */
  if(!block) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: unable to find %p with %llu bytes on private heap, calling sqlcipher_internal_free fallback", __func__, mem, sz);
    sqlcipher_internal_free(mem, sz);
  } else {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s freed %llu bytes on private heap at %p", __func__, sz, mem);
  }
}

int sqlcipher_register_provider(sqlcipher_provider *p) {
  int preexisting = 0, rc = SQLITE_OK;
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER", __func__);

  if(!p || default_provider == p) {
    goto cleanup;
  }

  if(!default_provider) {
    /* initial provider registration, NULL out previous pointer*/
    p->next = NULL;
  } else {
    /* one or more previous provider has already been registered, search through
     * the list to see if the new provider has already been registered and handle
     * appropriately */
    sqlcipher_provider *previous = default_provider;
    sqlcipher_provider *current = default_provider->next;
    while(current) {
      if(current == p) {
        /* this is a duplicate provider registration, and the provider in question
         * already exists on the list. In that case, pop it out so it can be moved up to default.
         * note that if we found an existing match we should avoid re-initializing the provider */
        previous->next = current->next;
        preexisting = 1;
        break;
      }
      previous = current;
      current = current->next;
    }
    /* the current default_provider gets tacked on the list */
    p->next = default_provider;
  }

  /* the new provider is elevated to default. if the provider was not preexisting and it has an initializer, call it */
  if(!preexisting && p->init) {
    rc = p->init();
  }
 
  if(rc == SQLITE_OK) {
    default_provider = p;   
  }
cleanup:
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER", __func__);

  return rc;
}

/* return a pointer to the currently registered provider. This will
   allow an application to fetch the current registered provider and
   make minor changes to it */
sqlcipher_provider* sqlcipher_get_provider() {
  return default_provider;
}

char* sqlcipher_version(void) {
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
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_cipher_ctx_init: allocating context");
  *iCtx = (cipher_ctx *) sqlcipher_malloc(sizeof(cipher_ctx));
  c_ctx = *iCtx;
  if(c_ctx == NULL) return SQLITE_NOMEM;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_cipher_ctx_init: allocating key");
  c_ctx->key = (unsigned char *) sqlcipher_malloc(ctx->key_sz);

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_cipher_ctx_init: allocating hmac_key");
  c_ctx->hmac_key = (unsigned char *) sqlcipher_malloc(ctx->key_sz);

  if(!c_ctx->key || !c_ctx->hmac_key) return SQLITE_NOMEM;

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx
  */
static void sqlcipher_cipher_ctx_free(codec_ctx* ctx, cipher_ctx **iCtx) {
  cipher_ctx *c_ctx = *iCtx;
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "cipher_ctx_free: iCtx=%p", iCtx);
  if(c_ctx->key) sqlcipher_free(c_ctx->key, ctx->key_sz);
  if(c_ctx->hmac_key) sqlcipher_free(c_ctx->hmac_key, ctx->key_sz);
  if(c_ctx->pass) sqlcipher_free(c_ctx->pass, c_ctx->pass_sz);
  sqlcipher_free(c_ctx, sizeof(cipher_ctx)); 
}

static int sqlcipher_codec_ctx_reserve_setup(codec_ctx *ctx) {
  int base_reserve = ctx->iv_sz; /* base reserve size will be IV only */ 
  int reserve = base_reserve;

  ctx->hmac_sz = ctx->provider->get_hmac_sz(ctx->provider_ctx, ctx->hmac_algorithm); 

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC))
    reserve += ctx->hmac_sz; /* if reserve will include hmac, update that size */

  /* calculate the amount of reserve needed in even increments of the cipher block size */
  if(ctx->block_sz > 0) {
    reserve = ((reserve % ctx->block_sz) == 0) ? reserve :
               ((reserve / ctx->block_sz) + 1) * ctx->block_sz;  
  }

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_reserve_setup: base_reserve=%d block_sz=%d md_size=%d reserve=%d", 
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

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_cipher_ctx_cmp: c1=%p c2=%p sqlcipher_memcmp(c1->pass, c2_pass)=%d are_equal=%d",
    c1, c2,
    (c1->pass == NULL || c2->pass == NULL) ?
      -1 :
      sqlcipher_memcmp(
        (const unsigned char*)c1->pass,
        (const unsigned char*)c2->pass,
        c1->pass_sz
      ),
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

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_cipher_ctx_copy: target=%p, source=%p", target, source);
  if(target->pass) sqlcipher_free(target->pass, target->pass_sz);
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
  return SQLITE_OK;
}

/**
  * Get the keyspec for the cipher_ctx
  * 
  * returns SQLITE_OK if assignment was successfull
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_get_keyspec(codec_ctx *ctx, cipher_ctx *c_ctx, char **keyspec_ptr, int *keyspec_sz) {
  int sz = 0;
  char *keyspec = NULL, *out = NULL;

  if(keyspec_ptr == NULL) return SQLITE_NOMEM;

  /* establish the size for a hex-formated key specification, containing the
   * raw encryption key, optional hmac key, and the salt used to generate it.
   * The format will be either:
   *   x'hex(key)...hex(hmac_key)...hex(salt)'
   *     or
   *   x'hex(key)...hex(salt)'
   *. The contents are SQLite BLOB formatted, so oversize by 3 bytes for the leading
   * x' and trailing ' characters required by the spec*/
  if(ctx->flags & CIPHER_FLAG_HMAC) { /* if HMAC is enabled, encode key, hmac key, and salt */
    sz = ((ctx->key_sz + ctx->key_sz + ctx->kdf_salt_sz) * 2) + 3;
  } else { /* otherwise encode key and salt */
    sz = ((ctx->key_sz + ctx->kdf_salt_sz) * 2) + 3;
  }

  *keyspec_ptr = sqlcipher_malloc(sz);
  keyspec = *keyspec_ptr;

  if(keyspec == NULL) return SQLITE_NOMEM;

  keyspec[0] = 'x';
  keyspec[1] = '\'';

  out = keyspec + 2;

  /* start with the encryption key */
  sqlcipher_shield(c_ctx->key, ctx->key_sz);
  cipher_bin2hex(c_ctx->key, ctx->key_sz, out);
  sqlcipher_shield(c_ctx->key, ctx->key_sz);
  out += ctx->key_sz * 2;

  if(ctx->flags & CIPHER_FLAG_HMAC) {
    /* add the hmac key after the encryption key if HMAC is in use*/
    sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);
    cipher_bin2hex(c_ctx->hmac_key, ctx->key_sz, out);
    sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);
    out += ctx->key_sz * 2;
  }

  /* finally encode the salt last */
  cipher_bin2hex(ctx->kdf_salt, ctx->kdf_salt_sz, out);

  keyspec[sz - 1] = '\'';
  *keyspec_sz = sz;

  return SQLITE_OK;
}

static void sqlcipher_set_derive_key(codec_ctx *ctx, int derive) {
  if(ctx->read_ctx != NULL) ctx->read_ctx->derive_key = derive;
  if(ctx->write_ctx != NULL) ctx->write_ctx->derive_key = derive;
}

/**
  * Set the passphrase for the cipher_ctx
  * 
  * returns SQLITE_OK if assignment was successfull
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_set_pass(cipher_ctx *ctx, const void *zKey, int nKey) {
  /* free, zero existing pointers and size */
  if(ctx->pass) sqlcipher_free(ctx->pass, ctx->pass_sz);
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

static int sqlcipher_codec_ctx_set_pass(codec_ctx *ctx, const void *zKey, int nKey, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  if((rc = sqlcipher_cipher_ctx_set_pass(c_ctx, zKey, nKey)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_set_pass: error %d from sqlcipher_cipher_ctx_set_pass", rc);
    return rc;
  }

  c_ctx->derive_key = 1;

  if(for_ctx == 2) {
    if((rc = sqlcipher_cipher_ctx_copy(ctx, for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_set_pass: error %d from sqlcipher_cipher_ctx_copy", rc);
      return rc;
    }
  }

  return SQLITE_OK;
} 

static int sqlcipher_codec_ctx_set_kdf_iter(codec_ctx *ctx, int kdf_iter) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;
  ctx->kdf_iter = kdf_iter;
  sqlcipher_set_derive_key(ctx, 1);
  return SQLITE_OK;
}

static int sqlcipher_codec_ctx_set_fast_kdf_iter(codec_ctx *ctx, int fast_kdf_iter) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  ctx->fast_kdf_iter = fast_kdf_iter;
  sqlcipher_set_derive_key(ctx, 1);
  return SQLITE_OK;
}

/* set the global default flag for HMAC */
static void sqlcipher_set_default_use_hmac(int use) {
  if(use) SQLCIPHER_FLAG_SET(default_flags, CIPHER_FLAG_HMAC);
  else SQLCIPHER_FLAG_UNSET(default_flags,CIPHER_FLAG_HMAC);
}

/* set the codec flag for whether this individual database should be using hmac */
static int sqlcipher_codec_ctx_set_use_hmac(codec_ctx *ctx, int use) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(use) {
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HMAC);
  } else {
    SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_HMAC);
  } 

  return sqlcipher_codec_ctx_reserve_setup(ctx);
}

/* the length of plaintext header size must be:
 * 1. greater than or equal to zero
 * 2. a multiple of the cipher block size
 * 3. less than or equal to the non-reserve size of the first database page
 *
 * Note: it is possible to leave the entire first page in plaintext. This is discouraged since it will
 * likely leak some small amount of schema data, but it's required to support use of the recovery VFS.
 * see comment in sqlcipher_page_cipher for more details.
 */
static int sqlcipher_codec_ctx_set_plaintext_header_size(codec_ctx *ctx, int size) {
  if(size >= 0 && ctx->block_sz > 0 && (size % ctx->block_sz) == 0 && size <= (ctx->page_sz - ctx->reserve_sz)) {
    ctx->plaintext_header_sz = size;
    return SQLITE_OK;
  }
  ctx->plaintext_header_sz = -1;
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: attempt to set invalid plantext_header_size %d", __func__, size);
  return SQLITE_ERROR;
} 

static int sqlcipher_codec_ctx_set_hmac_algorithm(codec_ctx *ctx, int algorithm) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  ctx->hmac_algorithm = algorithm;
  return sqlcipher_codec_ctx_reserve_setup(ctx);
} 

static int sqlcipher_codec_ctx_set_kdf_algorithm(codec_ctx *ctx, int algorithm) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  ctx->kdf_algorithm = algorithm;
  return SQLITE_OK;
} 

static void sqlcipher_codec_ctx_set_error(codec_ctx *ctx, int error) {
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_set_error %d", error);
  sqlite3pager_error(sqlite3BtreePager(ctx->pBt), error);
  ctx->pBt->pBt->db->errCode = error;
  ctx->error = error;
}

static int sqlcipher_codec_ctx_init_kdf_salt(codec_ctx *ctx) {
  sqlite3_file *fd = sqlite3PagerFile(sqlite3BtreePager(ctx->pBt));

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT)) {
    return SQLITE_OK; /* don't reload salt when not needed */
  }

  /* read salt from header, if present, otherwise generate a new random salt */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init_kdf_salt: obtaining salt");
  if(fd == NULL || fd->pMethods == 0 || sqlite3OsRead(fd, ctx->kdf_salt, ctx->kdf_salt_sz, 0) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init_kdf_salt: unable to read salt from file header, generating random");
    if(ctx->provider->random(ctx->provider_ctx, ctx->kdf_salt, ctx->kdf_salt_sz) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init_kdf_salt: error retrieving random bytes from provider");
      return SQLITE_ERROR;
    }
  }
  SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT);
  return SQLITE_OK; 
}

static int sqlcipher_codec_ctx_set_kdf_salt(codec_ctx *ctx, unsigned char *salt, int size) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(size >= ctx->kdf_salt_sz) {
    memcpy(ctx->kdf_salt, salt, ctx->kdf_salt_sz);
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT);
    return SQLITE_OK;
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_set_kdf_salt: attempt to set salt of incorrect size %d", size);
  return SQLITE_ERROR;
}

static int sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx, void** salt) {
  int rc = SQLITE_OK;
  if(!SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT)) {
    if((rc = sqlcipher_codec_ctx_init_kdf_salt(ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_get_kdf_salt: error %d from sqlcipher_codec_ctx_init_kdf_salt", rc);
    }
  }
  *salt = ctx->kdf_salt;

  return rc;
}

static int sqlcipher_codec_ctx_set_pagesize(codec_ctx *ctx, int size) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(!((size != 0) && ((size & (size - 1)) == 0)) || size < 512 || size > 65536) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "cipher_page_size not a power of 2 and between 512 and 65536 inclusive");
    return SQLITE_ERROR;
  }
  /* attempt to free the existing page buffer */
  if(ctx->buffer) sqlcipher_free(ctx->buffer,ctx->page_sz);
  ctx->page_sz = size;

  /* pre-allocate a page buffer of PageSize bytes. This will
     be used as a persistent buffer for encryption and decryption 
     operations to avoid overhead of multiple memory allocations*/
  ctx->buffer = sqlcipher_malloc(size);
  if(ctx->buffer == NULL) return SQLITE_NOMEM;

  return SQLITE_OK;
}

static int sqlcipher_codec_ctx_init(codec_ctx **iCtx, Db *pDb, Pager *pPager, const void *zKey, int nKey) {
  int rc;
  codec_ctx *ctx;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_codec_ctx_init: allocating context");

  *iCtx = sqlcipher_malloc(sizeof(codec_ctx));
  ctx = *iCtx;

  if(ctx == NULL) return SQLITE_NOMEM;

  ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */

  /* allocate space for salt data. Then read the first 16 bytes 
       directly off the database file. This is the salt for the
       key derivation function. If we get a short read allocate
       a new random salt value */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_codec_ctx_init: allocating kdf_salt");
  ctx->kdf_salt_sz = FILE_HEADER_SZ;
  ctx->kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz);
  if(ctx->kdf_salt == NULL) return SQLITE_NOMEM;

  /* allocate space for separate hmac salt data. We want the
     HMAC derivation salt to be different than the encryption
     key derivation salt */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "sqlcipher_codec_ctx_init: allocating hmac_kdf_salt");
  ctx->hmac_kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz);
  if(ctx->hmac_kdf_salt == NULL) return SQLITE_NOMEM;

  /* setup default flags */
  ctx->flags = default_flags;

  /* the context will use the current default crypto provider  */
  ctx->provider = default_provider;

  if((rc = ctx->provider->ctx_init(&ctx->provider_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d returned from ctx_init", rc);
    return rc;
  }

  ctx->key_sz = ctx->provider->get_key_sz(ctx->provider_ctx);
  ctx->iv_sz = ctx->provider->get_iv_sz(ctx->provider_ctx);
  ctx->block_sz = ctx->provider->get_block_sz(ctx->provider_ctx);

  /*
     Always overwrite page size and set to the default because the first page of the database
     in encrypted and thus sqlite can't effectively determine the pagesize. this causes an issue in 
     cases where bytes 16 & 17 of the page header are a power of 2 as reported by John Lehman
  */
  if((rc = sqlcipher_codec_ctx_set_pagesize(ctx, default_page_size)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d returned from sqlcipher_codec_ctx_set_pagesize with %d", rc, default_page_size);
    return rc;
  }

  /* establish settings for the KDF iterations and fast (HMAC) KDF iterations */
  if((rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, default_kdf_iter)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting default_kdf_iter %d", rc, default_kdf_iter);
    return rc;
  }

  if((rc = sqlcipher_codec_ctx_set_fast_kdf_iter(ctx, FAST_PBKDF2_ITER)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting fast_kdf_iter to %d", rc, FAST_PBKDF2_ITER);
    return rc;
  }

  /* set the default HMAC and KDF algorithms which will determine the reserve size */
  if((rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, default_hmac_algorithm)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting sqlcipher_codec_ctx_set_hmac_algorithm with %d", rc, default_hmac_algorithm);
    return rc;
  }

  /* Note that use_hmac is a special case that requires recalculation of page size
     so we call set_use_hmac to perform setup */
  if((rc = sqlcipher_codec_ctx_set_use_hmac(ctx, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC))) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting use_hmac %d", rc, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC));
    return rc;
  }

  if((rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, default_kdf_algorithm)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting sqlcipher_codec_ctx_set_kdf_algorithm with %d", rc, default_kdf_algorithm);
    return rc;
  }

  /* setup the default plaintext header size */
  if((rc = sqlcipher_codec_ctx_set_plaintext_header_size(ctx, default_plaintext_header_size)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting sqlcipher_codec_ctx_set_plaintext_header_size with %d", rc, default_plaintext_header_size);
    return rc;
  }

  /* initialize the read and write sub-contexts. this must happen after key_sz is established  */
  if((rc = sqlcipher_cipher_ctx_init(ctx, &ctx->read_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d initializing read_ctx", rc);
    return rc;
  } 

  if((rc = sqlcipher_cipher_ctx_init(ctx, &ctx->write_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d initializing write_ctx", rc);
    return rc; 
  }

  /* set the key material on one of the sub cipher contexts and sync them up */
  if((rc = sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, 0)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d setting pass key", rc);
    return rc;
  }

  if((rc = sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_init: error %d copying write_ctx to read_ctx", rc);
    return rc;
  }

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx, including the allocated
  * read_ctx and write_ctx.
  */
static void sqlcipher_codec_ctx_free(codec_ctx **iCtx) {
  codec_ctx *ctx = *iCtx;
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "codec_ctx_free: iCtx=%p", iCtx);
  if(ctx->kdf_salt) sqlcipher_free(ctx->kdf_salt, ctx->kdf_salt_sz);
  if(ctx->hmac_kdf_salt) sqlcipher_free(ctx->hmac_kdf_salt, ctx->kdf_salt_sz);
  if(ctx->buffer) sqlcipher_free(ctx->buffer, ctx->page_sz);
  if(ctx->provider) ctx->provider->ctx_free(&ctx->provider_ctx);

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
  int rc;
  /* we may convert page number to consistent representation before calculating MAC for
     compatibility across big-endian and little-endian platforms. 

     Note: The public release of sqlcipher 2.0.0 to 2.0.6 had a bug where the bytes of pgno 
     were used directly in the MAC. SQLCipher convert's to little endian by default to preserve
     backwards compatibility on the most popular platforms, but can optionally be configured
     to use either big endian or native byte ordering via pragma. */

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_LE_PGNO)) { /* compute hmac using little endian pgno*/
    sqlcipher_put4byte_le(pgno_raw, pgno);
  } else if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_BE_PGNO)) { /* compute hmac using big endian pgno */
    sqlite3Put4byte(pgno_raw, pgno); /* sqlite3Put4byte converts 32bit uint to big endian  */
  } else { /* use native byte ordering */
    memcpy(pgno_raw, &pgno, sizeof(pgno));
  }

  /* include the encrypted page data,  initialization vector, and page number in HMAC. This will 
     prevent both tampering with the ciphertext, manipulation of the IV, or resequencing otherwise
     valid pages out of order in a database */ 
  sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);
  rc = ctx->provider->hmac(
    ctx->provider_ctx, ctx->hmac_algorithm, c_ctx->hmac_key,
    ctx->key_sz, in,
    in_sz, (unsigned char*) &pgno_raw,
    sizeof(pgno), out);
  sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);

  return rc;
}

/*
 * ctx - codec context
 * pgno - page number in database
 * size - size in bytes of input and output buffers
 * mode - 1 to encrypt, 0 to decrypt
 * in - pointer to input bytes
 * out - pouter to output bytes
 */
static int sqlcipher_page_cipher(codec_ctx *ctx, int for_ctx, Pgno pgno, int mode, int page_sz, unsigned char *in, unsigned char *out) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  unsigned char *iv_in, *iv_out, *hmac_in, *hmac_out, *out_start;
  int size, rc;

  /* calculate some required positions into various buffers */
  size = page_sz - ctx->reserve_sz; /* adjust size to useable size and memset reserve at end of page */
  iv_out = out + size;
  iv_in = in + size;

  /* if the full amount of the first page (excluding reserve size), e.g. 4016 bytes for a 4096 byte page size with HMAC_SHA512,
   * is used as a plaintext header, then the entire first page will be completely plaintext, and this function should just return early.
   * This should almost never occur during normal usage, so we will log at WARN level, but it is required in the special case that
   * a user wants to attempt recovery on an encrypted database. In that case, the database header must be completely plaintext so that
   * the recovery VFS can be used with it's special 1st page logic */
  if(pgno == 1 && size == 0) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: skipping encryption/decryption for fully  plaintext header", __func__);
    return SQLITE_OK;
  }

  /* hmac will be written immediately after the initialization vector. the remainder of the page reserve will contain
     random bytes. note, these pointers are only valid when using hmac */
  hmac_in = in + size + ctx->iv_sz; 
  hmac_out = out + size + ctx->iv_sz;
  out_start = out; /* note the original position of the output buffer pointer, as out will be rewritten during encryption */

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: pgno=%d, mode=%d, size=%d", __func__, pgno, mode, size);
  CODEC_HEXDUMP("sqlcipher_page_cipher: input page data", in, page_sz);

  /* the key size should never be zero. If it is, error out. */
  if(ctx->key_sz == 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error possible context corruption, key_sz is zero for pgno=%d", __func__, pgno);
    goto error;
  } 

  if(mode == CIPHER_ENCRYPT) {
    /* start at front of the reserve block, write random data to the end */
    if(ctx->provider->random(ctx->provider_ctx, iv_out, ctx->reserve_sz) != SQLITE_OK) goto error;
  } else { /* CIPHER_DECRYPT */
    memcpy(iv_out, iv_in, ctx->iv_sz); /* copy the iv from the input to output buffer */
  } 

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) && (mode == CIPHER_DECRYPT)) {
    if(sqlcipher_page_hmac(ctx, c_ctx, pgno, in, size + ctx->iv_sz, hmac_out) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: hmac operation on decrypt failed for pgno=%d", __func__, pgno);
      goto error;
    }

    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: comparing hmac on in=%p out=%p hmac_sz=%d", __func__, hmac_in, hmac_out, ctx->hmac_sz);
    if(sqlcipher_memcmp(hmac_in, hmac_out, ctx->hmac_sz) != 0) { /* the hmac check failed */ 
      if(sqlite3BtreeGetAutoVacuum(ctx->pBt) != BTREE_AUTOVACUUM_NONE && sqlcipher_ismemset(in, 0, page_sz) == 0) {
        /* first check if the entire contents of the page is zeros. If so, this page 
           resulted from a short read (i.e. sqlite attempted to pull a page after the end of the file. these 
           short read failures must be ignored for autovaccum mode to work so wipe the output buffer 
           and return SQLITE_OK to skip the decryption step. */
        sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: zeroed page (short read) for pgno %d with autovacuum enabled", __func__, pgno);
        sqlcipher_memset(out, 0, page_sz); 
        return SQLITE_OK;
      } else {
        /* if the page memory is not all zeros, it means the there was data and a hmac on the page. 
           since the check failed, the page was either tampered with or corrupted. wipe the output buffer,
           and return SQLITE_ERROR to the caller */
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: hmac check failed for pgno=%d", __func__, pgno);
        goto error;
      }
    }
  } 
  
  sqlcipher_shield(c_ctx->key, ctx->key_sz);
  rc = ctx->provider->cipher(ctx->provider_ctx, mode, c_ctx->key, ctx->key_sz, iv_out, in, size, out);
  sqlcipher_shield(c_ctx->key, ctx->key_sz);

  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: cipher operation mode=%d failed for pgno=%d", __func__, mode, pgno);
    goto error;
  };
 
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) && (mode == CIPHER_ENCRYPT)) {
    if(sqlcipher_page_hmac(ctx, c_ctx, pgno, out_start, size + ctx->iv_sz, hmac_out) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: hmac operation on encrypt failed for pgno=%d", __func__, pgno);
      goto error;
    }; 
  }

  CODEC_HEXDUMP("sqlcipher_page_cipher: output page data", out_start, page_sz);

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
  int rc, raw_key_sz = 0, raw_salt_sz = 0, blob_format = 0, derive_hmac_key = 1;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: ctx->kdf_salt_sz=%d ctx->kdf_iter=%d ctx->fast_kdf_iter=%d ctx->key_sz=%d",
    __func__, ctx->kdf_salt_sz, ctx->kdf_iter, ctx->fast_kdf_iter, ctx->key_sz);

  /* if key material is present on the context for derivation */
  if(!c_ctx->pass || !c_ctx->pass_sz) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_cipher_ctx_key_derive: key material is not present on the context for key derivation");
    return SQLITE_ERROR;
  }

  /* if necessary, initialize the salt from the header or random source */
  if(!SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT)) {
    if((rc = sqlcipher_codec_ctx_init_kdf_salt(ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d from sqlcipher_codec_ctx_init_kdf_salt", __func__, rc);
      goto error;
    }
  }

  /* raw hey hex encoded is 2x long */
  raw_key_sz = ctx->key_sz * 2;
  raw_salt_sz = ctx->kdf_salt_sz *2;

  /* raw key must be BLOB formatted:
   * 1. greater than or equal to 5 characters long
   * 2. starting with x'
   * 3. ending with '
   * 4. length of contents between the x' and ' must be a power of 2
   * 5. contents must be hex */
  blob_format =
    c_ctx->pass_sz >= 5
    && sqlite3StrNICmp((const char *)c_ctx->pass ,"x'", 2) == 0
    && c_ctx->pass[c_ctx->pass_sz - 1] == '\''
    && (c_ctx->pass_sz - 3) % 2 == 0
    && cipher_isHex(c_ctx->pass + 2, c_ctx->pass_sz - 3);

  if(blob_format && c_ctx->pass_sz == raw_key_sz + 3) {
    /* option 1 - raw key consisting of only the encryption key */
    const unsigned char *z = c_ctx->pass + 2; /* adjust lead offset of x' */
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw key only", __func__);
    cipher_hex2bin(z, raw_key_sz, c_ctx->key);
  } else if(blob_format && c_ctx->pass_sz == raw_key_sz + raw_salt_sz + 3) {
    /* option 2 - raw key consisting of the encryption key and salt */
    const unsigned char *z = c_ctx->pass + 2;
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw key and salt", __func__);
    cipher_hex2bin(z, raw_key_sz, c_ctx->key);
    cipher_hex2bin(z + raw_key_sz, raw_salt_sz, ctx->kdf_salt);
  } else if(blob_format && c_ctx->pass_sz == raw_key_sz + raw_key_sz + raw_salt_sz + 3) {
    /* option 3 - raw key consisting of the encryption key, then hmac key, then salt */
    const unsigned char *z = c_ctx->pass + 2;
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw key, hmac key, and salt", __func__);
    cipher_hex2bin(z, raw_key_sz, c_ctx->key);
    cipher_hex2bin(z + raw_key_sz, raw_key_sz, c_ctx->hmac_key);
    cipher_hex2bin(z + raw_key_sz + raw_key_sz, raw_salt_sz, ctx->kdf_salt);
    derive_hmac_key = 0;
  } else {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: deriving key using PBKDF2 with %d iterations", __func__, ctx->kdf_iter);
    if((rc = ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->pass, c_ctx->pass_sz,
                  ctx->kdf_salt, ctx->kdf_salt_sz, ctx->kdf_iter,
                  ctx->key_sz, c_ctx->key)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred from provider kdf generating encryption key", __func__, rc);
      goto error;
    }
  }

  /* if this context is setup to use hmac checks, and we didn't already get an hmac
   * key inbound via keyspec / raw key, then generate a seperate
   * key for HMAC. In this case, we use the output of the previous KDF as the input to
   * this KDF run. This ensures a distinct but predictable HMAC key. */
  if(ctx->flags & CIPHER_FLAG_HMAC && derive_hmac_key) {
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

    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: deriving hmac key from encryption key using PBKDF2 with %d iterations",
      __func__, ctx->fast_kdf_iter);

    if((rc = ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->key, ctx->key_sz,
                  ctx->hmac_kdf_salt, ctx->kdf_salt_sz, ctx->fast_kdf_iter,
                  ctx->key_sz, c_ctx->hmac_key)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error occurred from provider kdf generating HMAC key", __func__, rc);
      goto error;
    }
  }

  sqlcipher_shield(c_ctx->key, ctx->key_sz);
  sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);
  c_ctx->derive_key = 0;
  return SQLITE_OK;

error:
  /* if an error occurred, overwrite any derived key material */
  xoshiro_randomness(c_ctx->key, ctx->key_sz);
  xoshiro_randomness(c_ctx->hmac_key, ctx->key_sz);
  return SQLITE_ERROR;
}

static int sqlcipher_codec_key_derive(codec_ctx *ctx) {
  /* derive key on first use if necessary */
  if(ctx->read_ctx->derive_key) {
    if(sqlcipher_cipher_ctx_key_derive(ctx, ctx->read_ctx) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_key_derive: error occurred deriving read_ctx key");
      return SQLITE_ERROR;
    }
  }

  if(ctx->write_ctx->derive_key) {
    if(sqlcipher_cipher_ctx_cmp(ctx->write_ctx, ctx->read_ctx) == 0) {
      /* the relevant parameters are the same, just copy read key */
      if(sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_key_derive: error occurred copying read_ctx to write_ctx");
        return SQLITE_ERROR;
      }
    } else {
      if(sqlcipher_cipher_ctx_key_derive(ctx, ctx->write_ctx) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_key_derive: error occurred deriving write_ctx key");
        return SQLITE_ERROR;
      }
    }
  }

  /* wipe and free passphrase after key derivation */
  if(ctx->store_pass  != 1) {
    sqlcipher_cipher_ctx_set_pass(ctx->read_ctx, NULL, 0);
    sqlcipher_cipher_ctx_set_pass(ctx->write_ctx, NULL, 0);
  }

  return SQLITE_OK; 
}

static int sqlcipher_codec_key_copy(codec_ctx *ctx, int source) {
  if(source == CIPHER_READ_CTX) { 
      return sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx); 
  } else {
      return sqlcipher_cipher_ctx_copy(ctx, ctx->read_ctx, ctx->write_ctx); 
  }
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

static int sqlcipher_codec_ctx_integrity_check(codec_ctx *ctx, Parse *pParse, char *column) {
  Pgno page = 1;
  int rc = 0;
  char *result;
  unsigned char *hmac_out = NULL;
  sqlite3_file *fd = sqlite3PagerFile(sqlite3BtreePager(ctx->pBt));
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
    i64 offset = (page - 1) * ctx->page_sz;
    int payload_sz = ctx->page_sz - ctx->reserve_sz + ctx->iv_sz;
    int read_sz = ctx->page_sz;

    /* skip integrity check on PAGER_SJ_PGNO since it will have no valid content */
    if(sqlite3pager_is_sj_pgno(sqlite3BtreePager(ctx->pBt), page)) continue;

    if(page==1) {
      int page1_offset = ctx->plaintext_header_sz ? ctx->plaintext_header_sz : FILE_HEADER_SZ;
      read_sz = read_sz - page1_offset;
      payload_sz = payload_sz - page1_offset;
      offset += page1_offset;
    }

    sqlcipher_memset(ctx->buffer, 0, ctx->page_sz);
    sqlcipher_memset(hmac_out, 0, ctx->hmac_sz);
    if(sqlite3OsRead(fd, ctx->buffer, read_sz, offset) != SQLITE_OK) {
      result = sqlite3_mprintf("error reading %d bytes from file page %d at offset %d", read_sz, page, offset);
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
    result = sqlite3_mprintf("page %d has an invalid size of %lld bytes (expected %d bytes)", page, file_sz - ((file_sz / ctx->page_sz) * ctx->page_sz), ctx->page_sz);
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
  }

cleanup:
  if(hmac_out != NULL) sqlcipher_free(hmac_out, ctx->hmac_sz);
  return SQLITE_OK;
}

static int sqlcipher_codec_ctx_migrate(codec_ctx *ctx) {
  int i, pass_sz, keyspec_sz, nRes, user_version, rc, rc_cleanup, oflags;
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
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: no upgrade required - exiting");
    goto cleanup;
  }

  for(i = 3; i > 0; i--) {
    pragma_compat = sqlite3_mprintf("PRAGMA cipher_compatibility = %d;", i);
    rc = sqlcipher_check_connection(db_filename, pass, pass_sz, pragma_compat, &user_version, &journal_mode);
    if(rc == SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: version %d format found", i);
      goto migrate;
    }
    if(pragma_compat) sqlcipher_free(pragma_compat, sqlite3Strlen30(pragma_compat)); 
    pragma_compat = NULL;
  }
  
  /* if we exit the loop normally we failed to determine the version, this is an error */
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: unable to determine format version for upgrade: this may indicate custom settings were used ");
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
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: set compatibility mode failed, error code %d", rc);
    goto handle_error;
  }

  /* force journal mode to DELETE, we will set it back later if different */
  rc = sqlite3_exec(db, "PRAGMA journal_mode = delete;", NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: force journal mode DELETE failed, error code %d", rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, attach_command, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: attach failed, error code %d", rc);
    goto handle_error;
  }

  rc = sqlite3_key_v2(db, "migrate", pass, pass_sz);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: keying attached database failed, error code %d", rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, "SELECT sqlcipher_export('migrate');", NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: sqlcipher_export failed, error code %d", rc);
    goto handle_error;
  }

#ifdef SQLCIPHER_TEST
  if((cipher_test_flags & TEST_FAIL_MIGRATE) > 0) {
    rc = SQLITE_ERROR;
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: simulated migrate failure, error code %d", rc);
    goto handle_error;
  }
#endif

  rc = sqlite3_exec(db, set_user_version, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: set user version failed, error code %d", rc);
    goto handle_error;
  }

  if( !db->autoCommit ){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: cannot migrate from within a transaction");
    goto handle_error;
  }
  if( db->nVdbeActive>1 ){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: cannot migrate - SQL statements in progress");
    goto handle_error;
  }

  pDest = db->aDb[0].pBt;
  pDb = &(db->aDb[db->nDb-1]);
  pSrc = pDb->pBt;

  nRes = sqlite3BtreeGetRequestedReserve(pSrc);
  /* unset the BTS_PAGESIZE_FIXED flag to avoid SQLITE_READONLY */
  pDest->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED; 
  rc = sqlite3BtreeSetPageSize(pDest, default_page_size, nRes, 0);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: failed to set btree page size to %d res %d rc %d", default_page_size, nRes, rc);
    goto handle_error;
  }

  sqlcipherCodecGetKey(db, db->nDb - 1, (void**)&keyspec, &keyspec_sz);
  SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_KEY_USED);
  sqlcipherCodecAttach(db, 0, keyspec, keyspec_sz);
  
  srcfile = sqlite3PagerFile(sqlite3BtreePager(pSrc));
  destfile = sqlite3PagerFile(sqlite3BtreePager(pDest));

  sqlite3OsClose(srcfile);
  sqlite3OsClose(destfile); 

#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: performing windows MoveFileExA");

  w_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) db_filename, -1, NULL, 0);
  w_db_filename = sqlcipher_malloc(w_db_filename_sz * sizeof(wchar_t));
  w_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) db_filename, -1, (const LPWSTR) w_db_filename, w_db_filename_sz);

  w_migrated_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) migrated_db_filename, -1, NULL, 0);
  w_migrated_db_filename = sqlcipher_malloc(w_migrated_db_filename_sz * sizeof(wchar_t));
  w_migrated_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) migrated_db_filename, -1, (const LPWSTR) w_migrated_db_filename, w_migrated_db_filename_sz);

  if(!MoveFileExW(w_migrated_db_filename, w_db_filename, MOVEFILE_REPLACE_EXISTING)) {
    rc = SQLITE_ERROR;
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: error occurred while renaming migration files %d", rc);
    goto handle_error;
  }
#else
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: performing POSIX rename");
  if ((rc = rename(migrated_db_filename, db_filename)) != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: error occurred while renaming migration files %s to %s: %d", migrated_db_filename, db_filename, rc);
    goto handle_error;
  }
#endif
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: renamed migration database %s to main database %s: %d", migrated_db_filename, db_filename, rc);

  rc = sqlite3OsOpen(db->pVfs, migrated_db_filename, srcfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: failed to reopen migration database %s: %d", migrated_db_filename, rc);
    goto handle_error;
  }

  rc = sqlite3OsOpen(db->pVfs, db_filename, destfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: failed to reopen main database %s: %d", db_filename, rc);
    goto handle_error;
  }

  sqlite3pager_reset(sqlite3BtreePager(pDest));
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: reset pager");

handle_error:
  rc_cleanup = sqlite3_exec(db, "DETACH DATABASE migrate;", NULL, NULL, NULL);
  if(rc_cleanup != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: DETACH DATABASE migrate failed: %d", rc_cleanup);
    /* only overwrite the rc in the cleanup stage if it is currently not an error. This will prevent overwriting a previous error that occured earlier in migration */
    if(rc == SQLITE_OK) { 
      rc = rc_cleanup;
    }
  }

  sqlite3ResetAllSchemasOfConnection(db);
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: reset all schemas");

  if(journal_mode) {
    set_journal_mode = sqlite3_mprintf("PRAGMA journal_mode = %s;", journal_mode);
    rc_cleanup = sqlite3_exec(db, set_journal_mode, NULL, NULL, NULL);
    if(rc_cleanup != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: failed to re-set journal mode via %s: %d", set_journal_mode, rc_cleanup);
      if(rc == SQLITE_OK) {
        rc = rc_cleanup;
      }
    }
  }

  if(migrated_db_filename) {
    int del_rc = sqlite3OsDelete(db->pVfs, migrated_db_filename, 0);
    if(del_rc != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: failed to delete migration database %s: %d", migrated_db_filename, del_rc);
    }
  }

  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_ctx_migrate: an error occurred attempting to migrate the database - last error %d", rc);
    sqlite3pager_reset(sqlite3BtreePager(ctx->pBt));
    ctx->error = rc; /* set flag for deferred error */
  }

cleanup:
  if(pass) sqlcipher_free(pass, pass_sz);
  if(keyspec) sqlcipher_free(keyspec, keyspec_sz);
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

static int sqlcipher_codec_add_random(codec_ctx *ctx, const char *zRight, int random_sz){
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
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_add_random: using raw random blob from hex");
    random = sqlcipher_malloc(buffer_sz);
    memset(random, 0, buffer_sz);
    cipher_hex2bin(z, n, random);
    rc = ctx->provider->add_random(ctx->provider_ctx, random, buffer_sz);
    sqlcipher_free(random, buffer_sz);
    return rc;
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_add_random: attemt to add random with invalid format");
  return SQLITE_ERROR;
}

#if !defined(SQLITE_OMIT_TRACE)

#define SQLCIPHER_PROFILE_FMT        "Elapsed time:%.3f ms - %s\n"
#define SQLCIPHER_PROFILE_FMT_OSLOG  "Elapsed time:%{public}.3f ms - %{public}s\n"

static int sqlcipher_profile_callback(unsigned int trace, void *file, void *stmt, void *run_time){
  FILE *f = (FILE*) file;
  double elapsed = (*((sqlite3_uint64*)run_time))/1000000.0;
  if(f == NULL) {
#if !defined(SQLCIPHER_OMIT_LOG_DEVICE)
#if defined(__ANDROID__)
    __android_log_print(ANDROID_LOG_DEBUG, "sqlcipher", SQLCIPHER_PROFILE_FMT, elapsed, sqlite3_sql((sqlite3_stmt*)stmt));
#elif defined(__APPLE__)
    os_log(OS_LOG_DEFAULT, SQLCIPHER_PROFILE_FMT_OSLOG, elapsed, sqlite3_sql((sqlite3_stmt*)stmt));
#endif
#endif
  } else {
    fprintf(f, SQLCIPHER_PROFILE_FMT, elapsed, sqlite3_sql((sqlite3_stmt*)stmt));
  }
  return SQLITE_OK;
}
#endif

static int sqlcipher_cipher_profile(sqlite3 *db, const char *destination){
#if defined(SQLITE_OMIT_TRACE)
  return SQLITE_ERROR;
#else
  FILE *f = NULL;
  if(sqlite3_stricmp(destination, "off") == 0){
    sqlite3_trace_v2(db, 0, NULL, NULL); /* disable tracing */
  } else {
    if(sqlite3_stricmp(destination, "stdout") == 0){
      f = stdout;
    }else if(sqlite3_stricmp(destination, "stderr") == 0){
      f = stderr;
    }else if(sqlite3_stricmp(destination, "logcat") == 0 || sqlite3_stricmp(destination, "device") == 0){
      f = NULL; /* file pointer will be NULL indicating the device target (i.e. logcat or oslog). We will accept logcat for backwards compatibility */
    }else{
#if !defined(SQLCIPHER_PROFILE_USE_FOPEN) && (defined(_WIN32) && (__STDC_VERSION__ > 199901L) || defined(SQLITE_OS_WINRT))
      if(fopen_s(&f, destination, "a") != 0) return SQLITE_ERROR;
#else
      if((f = fopen(destination, "a")) == 0) return SQLITE_ERROR;
#endif    
    }
    sqlite3_trace_v2(db, SQLITE_TRACE_PROFILE, sqlcipher_profile_callback, f);
  }
  return SQLITE_OK;
#endif
}

static char *sqlcipher_get_log_level_str(unsigned int level) {
  switch(level) {
    case SQLCIPHER_LOG_ERROR:
      return "ERROR";
    case SQLCIPHER_LOG_WARN:
      return "WARN";
    case SQLCIPHER_LOG_INFO:
      return "INFO";
    case SQLCIPHER_LOG_DEBUG:
      return "DEBUG";
    case SQLCIPHER_LOG_TRACE:
      return "TRACE";
    case SQLCIPHER_LOG_ANY:
      return "ANY";
  }
  return "NONE";
}

static char *sqlcipher_get_log_source_str(unsigned int source) {
  switch(source) {
    case SQLCIPHER_LOG_NONE:
      return "NONE";
    case SQLCIPHER_LOG_CORE:
      return "CORE";
    case SQLCIPHER_LOG_MEMORY:
      return "MEMORY";
    case SQLCIPHER_LOG_MUTEX:
      return "MUTEX";
    case SQLCIPHER_LOG_PROVIDER:
      return "PROVIDER";
  }
  return "ANY";
}

static char *sqlcipher_get_log_sources_str(unsigned int source) {
  if(source == SQLCIPHER_LOG_NONE) {
    return sqlite3_mprintf("%s", "NONE");
  } else if (source == SQLCIPHER_LOG_ANY) {
    return sqlite3_mprintf("%s", "ANY");
  } else {
    char *sources = NULL;
    unsigned int flag;
    for(flag = SQLCIPHER_LOG_CORE; flag != 0; flag = flag << 1) {
      if(SQLCIPHER_FLAG_GET(source, flag)) {
        char *src = sqlcipher_get_log_source_str(flag);
        if(sources) {
          char *tmp = sqlite3_mprintf("%s %s", sources, src);
          sqlite3_free(sources);
          sources = tmp;
        } else {
          sources = sqlite3_mprintf("%s", src);
        }
      }
    }
    return sources;
  }
}

#ifndef SQLCIPHER_OMIT_LOG
/* constants from https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-crt/misc/gettimeofday.c */
#define FILETIME_1970 116444736000000000ull /* seconds between 1/1/1601 and 1/1/1970 */
#define HECTONANOSEC_PER_SEC 10000000ull
#define MAX_LOG_LEN 8192
void sqlcipher_log(unsigned int level, unsigned int source, const char *message, ...) {
  va_list params;
  va_start(params, message);
  char formatted[MAX_LOG_LEN];
  size_t len = 0;

#ifdef CODEC_DEBUG
#if defined(SQLCIPHER_OMIT_LOG_DEVICE) || (!defined(__ANDROID__) && !defined(__APPLE__))
    vfprintf(stderr, message, params);
    fprintf(stderr, "\n");
    goto end;
#else
#if defined(__ANDROID__)
    __android_log_vprint(ANDROID_LOG_DEBUG, "sqlcipher", message, params);
    goto end;
#elif defined(__APPLE__)
    sqlite3_vsnprintf(MAX_LOG_LEN, formatted, message, params);
    os_log(OS_LOG_DEFAULT, "%{public}s", formatted);
    goto end;
#endif
#endif
#endif
  if(
    level > sqlcipher_log_level /* log level is higher, e.g. level filter is at ERROR but this message is DEBUG */
    || !SQLCIPHER_FLAG_GET(sqlcipher_log_source, source) /* source filter doesn't match this message source */
    || (sqlcipher_log_device == 0 && sqlcipher_log_file == NULL) /* no configured log target */
  ) {
    /* skip logging this message */
    goto end;
  }

  sqlite3_snprintf(MAX_LOG_LEN, formatted, "%s %s ", sqlcipher_get_log_level_str(level), sqlcipher_get_log_source_str(source));
  len = strlen(formatted);
  sqlite3_vsnprintf(MAX_LOG_LEN - (int) len, formatted + (int) len, message, params);

#if !defined(SQLCIPHER_OMIT_LOG_DEVICE)
  if(sqlcipher_log_device) {
#if defined(__ANDROID__)
    __android_log_write(ANDROID_LOG_DEBUG, "sqlcipher", formatted);
    goto end;
#elif defined(__APPLE__)
    os_log(OS_LOG_DEFAULT, "%{public}s", formatted);
    goto end;
#endif
  }
#endif

  if(sqlcipher_log_file != NULL){
    char buffer[24];
    struct tm tt;
    int ms;
    time_t sec;
#ifdef _WIN32
    SYSTEMTIME st;
    FILETIME ft;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    sec = (time_t) ((*((sqlite_int64*)&ft) - FILETIME_1970) / HECTONANOSEC_PER_SEC);
    ms = st.wMilliseconds;
    localtime_s(&tt, &sec);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    sec = tv.tv_sec;
    ms = tv.tv_usec/1000.0;
    localtime_r(&sec, &tt);
#endif
    if(strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tt)) {
      fprintf((FILE*)sqlcipher_log_file, "%s.%03d: %s\n", buffer, ms, formatted);
      goto end;
    }
  }

end:
  va_end(params);
}
#endif

static int sqlcipher_set_log(const char *destination){
#ifdef SQLCIPHER_OMIT_LOG
  return SQLITE_ERROR;
#else
  /* close open trace file if it is not stdout or stderr, then
     reset trace settings */
  if(sqlcipher_log_file != NULL && sqlcipher_log_file != stdout && sqlcipher_log_file != stderr) {
    fclose((FILE*)sqlcipher_log_file);
  }
  sqlcipher_log_file = NULL;
  sqlcipher_log_device = 0;

  if(sqlite3_stricmp(destination, "logcat") == 0 || sqlite3_stricmp(destination, "device") == 0){
    /* use the appropriate device log. accept logcat for backwards compatibility */
    sqlcipher_log_device = 1;
  } else if(sqlite3_stricmp(destination, "stdout") == 0){
    sqlcipher_log_file = stdout;
  }else if(sqlite3_stricmp(destination, "stderr") == 0){
    sqlcipher_log_file = stderr;
  }else if(sqlite3_stricmp(destination, "off") != 0){
#if !defined(SQLCIPHER_PROFILE_USE_FOPEN) && (defined(_WIN32) && (__STDC_VERSION__ > 199901L) || defined(SQLITE_OS_WINRT))
    if(fopen_s(&sqlcipher_log_file, destination, "a") != 0) return SQLITE_ERROR;
#else
    if((sqlcipher_log_file = fopen(destination, "a")) == 0) return SQLITE_ERROR;
#endif
  }
  sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "sqlcipher_set_log: set log to %s", destination);
  return SQLITE_OK;
#endif
}

static void sqlcipher_vdbe_return_string(Parse *pParse, const char *zLabel, const char *value, int value_type){
  Vdbe *v = sqlite3GetVdbe(pParse);
  sqlite3VdbeSetNumCols(v, 1);
  sqlite3VdbeSetColName(v, 0, COLNAME_NAME, zLabel, SQLITE_STATIC);
  sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, value, value_type);
  sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
}

static int codec_set_btree_to_codec_pagesize(sqlite3 *db, Db *pDb, codec_ctx *ctx) {
  int rc;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "codec_set_btree_to_codec_pagesize: sqlite3BtreeSetPageSize() size=%d reserve=%d", ctx->page_sz, ctx->reserve_sz);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "codec_set_btree_to_codec_pagesize: entering database mutex %p", db->mutex);
  sqlite3_mutex_enter(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "codec_set_btree_to_codec_pagesize: entered database mutex %p", db->mutex);
  db->nextPagesize = ctx->page_sz; 

  /* before forcing the page size we need to unset the BTS_PAGESIZE_FIXED flag, else  
     sqliteBtreeSetPageSize will block the change  */
  pDb->pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
  rc = sqlite3BtreeSetPageSize(pDb->pBt, ctx->page_sz, ctx->reserve_sz, 0);

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "codec_set_btree_to_codec_pagesize: sqlite3BtreeSetPageSize returned %d", rc);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "codec_set_btree_to_codec_pagesize: leaving database mutex %p", db->mutex);
  sqlite3_mutex_leave(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "codec_set_btree_to_codec_pagesize: left database mutex %p", db->mutex);

  return rc;
}

static int codec_set_pass_key(sqlite3* db, int nDb, const void *zKey, int nKey, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "codec_set_pass_key: db=%p nDb=%d for_ctx=%d", db, nDb, for_ctx);
  if(pDb->pBt) {
    codec_ctx *ctx = (codec_ctx*) sqlcipherPagerGetCodec(sqlite3BtreePager(pDb->pBt));

    if(ctx) {
      return sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, for_ctx);
    } else {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "codec_set_pass_key: error ocurred fetching codec from pager on db %d", nDb);
      return SQLITE_ERROR;
    }
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "codec_set_pass_key: no btree present on db %d", nDb);
  return SQLITE_ERROR;
} 

int sqlcipher_codec_pragma(sqlite3* db, int iDb, Parse *pParse, const char *zLeft, const char *zRight) {
  struct Db *pDb = &db->aDb[iDb];
  codec_ctx *ctx = NULL;
  int rc;

  if(pDb->pBt) {
    ctx = (codec_ctx*) sqlcipherPagerGetCodec(sqlite3BtreePager(pDb->pBt));
  }

  if(sqlite3_stricmp(zLeft, "key") !=0 && sqlite3_stricmp(zLeft, "rekey") != 0) {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_codec_pragma: db=%p iDb=%d pParse=%p zLeft=%s zRight=%s ctx=%p", db, iDb, pParse, zLeft, zRight, ctx);
  }

#ifdef SQLCIPHER_TEST
  if( sqlite3_stricmp(zLeft,"cipher_test_on")==0 ){
    if( zRight ) {
      if(sqlite3_stricmp(zRight, "fail_encrypt")==0) {
        SQLCIPHER_FLAG_SET(cipher_test_flags,TEST_FAIL_ENCRYPT);
      } else
      if(sqlite3_stricmp(zRight, "fail_decrypt")==0) {
        SQLCIPHER_FLAG_SET(cipher_test_flags,TEST_FAIL_DECRYPT);
      } else
      if(sqlite3_stricmp(zRight, "fail_migrate")==0) {
        SQLCIPHER_FLAG_SET(cipher_test_flags,TEST_FAIL_MIGRATE);
      }
    }
  } else
  if( sqlite3_stricmp(zLeft,"cipher_test_off")==0 ){
    if( zRight ) {
      if(sqlite3_stricmp(zRight, "fail_encrypt")==0) {
        SQLCIPHER_FLAG_UNSET(cipher_test_flags,TEST_FAIL_ENCRYPT);
      } else
      if(sqlite3_stricmp(zRight, "fail_decrypt")==0) {
        SQLCIPHER_FLAG_UNSET(cipher_test_flags,TEST_FAIL_DECRYPT);
      } else
      if(sqlite3_stricmp(zRight, "fail_migrate")==0) {
        SQLCIPHER_FLAG_UNSET(cipher_test_flags,TEST_FAIL_MIGRATE);
      }
    }
  } else
  if( sqlite3_stricmp(zLeft,"cipher_test")==0 ){
    char *flags = sqlite3_mprintf("%u", cipher_test_flags);
    sqlcipher_vdbe_return_string(pParse, "cipher_test", flags, P4_DYNAMIC);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_test_rand")==0 ){
    if( zRight ) {
      int rand = atoi(zRight);
      cipher_test_rand = rand;
    } else {
      char *rand = sqlite3_mprintf("%d", cipher_test_rand);
      sqlcipher_vdbe_return_string(pParse, "cipher_test_rand", rand, P4_DYNAMIC);
    }
  } else
#endif
  if( sqlite3_stricmp(zLeft, "cipher_fips_status")== 0 && !zRight ){
    if(ctx) {
      char *fips_mode_status = sqlite3_mprintf("%d", ctx->provider->fips_status(ctx->provider_ctx));
      sqlcipher_vdbe_return_string(pParse, "cipher_fips_status", fips_mode_status, P4_DYNAMIC);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_store_pass")==0 && zRight ) {
    if(ctx) {
      char *deprecation = "PRAGMA cipher_store_pass is deprecated, please remove from use";
      ctx->store_pass = sqlite3GetBoolean(zRight, 1);
      sqlcipher_vdbe_return_string(pParse, "cipher_store_pass", deprecation, P4_TRANSIENT);
      sqlite3_log(SQLITE_WARNING, deprecation);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_store_pass")==0 && !zRight ) {
    if(ctx){
      char *store_pass_value = sqlite3_mprintf("%d", ctx->store_pass);
      sqlcipher_vdbe_return_string(pParse, "cipher_store_pass", store_pass_value, P4_DYNAMIC);
    }
  }
  if( sqlite3_stricmp(zLeft, "cipher_profile")== 0 && zRight ){
      char *profile_status = sqlite3_mprintf("%d", sqlcipher_cipher_profile(db, zRight));
      sqlcipher_vdbe_return_string(pParse, "cipher_profile", profile_status, P4_DYNAMIC);
  } else
  if( sqlite3_stricmp(zLeft, "cipher_add_random")==0 && zRight ){
    if(ctx) {
      char *add_random_status = sqlite3_mprintf("%d", sqlcipher_codec_add_random(ctx, zRight, sqlite3Strlen30(zRight)));
      sqlcipher_vdbe_return_string(pParse, "cipher_add_random", add_random_status, P4_DYNAMIC);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_migrate")==0 && !zRight ){
    if(ctx){
      int status = sqlcipher_codec_ctx_migrate(ctx); 
      char *migrate_status = sqlite3_mprintf("%d", status);
      sqlcipher_vdbe_return_string(pParse, "cipher_migrate", migrate_status, P4_DYNAMIC);
      if(status != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlcipher_codec_pragma: error occurred during cipher_migrate: %d", status);
      }
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_provider")==0 && !zRight ){
    if(ctx) {
      sqlcipher_vdbe_return_string(pParse, "cipher_provider",
        ctx->provider->get_provider_name(ctx->provider_ctx), P4_TRANSIENT);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_provider_version")==0 && !zRight){
    if(ctx) {
      sqlcipher_vdbe_return_string(pParse, "cipher_provider_version",
        ctx->provider->get_provider_version(ctx->provider_ctx), P4_TRANSIENT);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_version")==0 && !zRight ){
    sqlcipher_vdbe_return_string(pParse, "cipher_version", sqlcipher_version(), P4_DYNAMIC);
  }else
  if( sqlite3_stricmp(zLeft, "cipher")==0 ){
    if(ctx) {
      if( zRight ) {
        const char* message = "PRAGMA cipher is no longer supported.";
        sqlcipher_vdbe_return_string(pParse, "cipher", message, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, message);
      }else {
        sqlcipher_vdbe_return_string(pParse, "cipher", 
          ctx->provider->get_cipher(ctx->provider_ctx), P4_TRANSIENT); 
      }
    }
  }else
  if( sqlite3_stricmp(zLeft, "rekey_cipher")==0 && zRight ){
    const char* message = "PRAGMA rekey_cipher is no longer supported.";
    sqlcipher_vdbe_return_string(pParse, "rekey_cipher", message, P4_TRANSIENT);
    sqlite3_log(SQLITE_WARNING, message);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_kdf_iter")==0 ){
    if( zRight ) {
      default_kdf_iter = atoi(zRight); /* change default KDF iterations */
    } else {
      char *kdf_iter = sqlite3_mprintf("%d", default_kdf_iter);
      sqlcipher_vdbe_return_string(pParse, "cipher_default_kdf_iter", kdf_iter, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft, "kdf_iter")==0 ){
    if(ctx) {
      if( zRight ) {
        sqlcipher_codec_ctx_set_kdf_iter(ctx, atoi(zRight)); /* change of RW PBKDF2 iteration */
      } else {
        char *kdf_iter = sqlite3_mprintf("%d", ctx->kdf_iter);
        sqlcipher_vdbe_return_string(pParse, "kdf_iter", kdf_iter, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft, "fast_kdf_iter")==0){
    if(ctx) {
      if( zRight ) {
        char *deprecation = "PRAGMA fast_kdf_iter is deprecated, please remove from use";
        sqlcipher_codec_ctx_set_fast_kdf_iter(ctx, atoi(zRight)); /* change of RW PBKDF2 iteration */
        sqlcipher_vdbe_return_string(pParse, "fast_kdf_iter", deprecation, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, deprecation);
      } else {
        char *fast_kdf_iter = sqlite3_mprintf("%d", ctx->fast_kdf_iter);
        sqlcipher_vdbe_return_string(pParse, "fast_kdf_iter", fast_kdf_iter, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft, "rekey_kdf_iter")==0 && zRight ){
    const char* message = "PRAGMA rekey_kdf_iter is no longer supported.";
    sqlcipher_vdbe_return_string(pParse, "rekey_kdf_iter", message, P4_TRANSIENT);
    sqlite3_log(SQLITE_WARNING, message);
  }else
  if( sqlite3_stricmp(zLeft,"page_size")==0 || sqlite3_stricmp(zLeft,"cipher_page_size")==0 ){
    /* PRAGMA cipher_page_size will alter the size of the database pages while ensuring that the
       required reserve space is allocated at the end of each page. This will also override the
       standard SQLite PRAGMA page_size behavior if a codec context is attached to the database handle.
       If PRAGMA page_size is invoked but a codec context is not attached (i.e. dealing with a standard
       unencrypted database) then return early and allow the standard PRAGMA page_size logic to apply. */
    if(ctx) {
      if( zRight ) {
        int size = atoi(zRight);
        rc = sqlcipher_codec_ctx_set_pagesize(ctx, size);
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      } else {
        char * page_size = sqlite3_mprintf("%d", ctx->page_sz);
        sqlcipher_vdbe_return_string(pParse, "cipher_page_size", page_size, P4_DYNAMIC);
      }
    } else {
      return 0; /* return early so that the PragTyp_PAGE_SIZE case logic in pragma.c will take effect */
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_page_size")==0 ){
    if( zRight ) {
      default_page_size = atoi(zRight);
    } else {
      char *page_size = sqlite3_mprintf("%d", default_page_size);
      sqlcipher_vdbe_return_string(pParse, "cipher_default_page_size", page_size, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_use_hmac")==0 ){
    if( zRight ) {
      sqlcipher_set_default_use_hmac(sqlite3GetBoolean(zRight,1));
    } else {
      char *default_use_hmac = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC));
      sqlcipher_vdbe_return_string(pParse, "cipher_default_use_hmac", default_use_hmac, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_use_hmac")==0 ){
    if(ctx) {
      if( zRight ) {
        rc = sqlcipher_codec_ctx_set_use_hmac(ctx, sqlite3GetBoolean(zRight,1));
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
        /* since the use of hmac has changed, the page size may also change */
        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      } else {
        char *hmac_flag = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC));
        sqlcipher_vdbe_return_string(pParse, "cipher_use_hmac", hmac_flag, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_pgno")==0 ){
    if(ctx) {
      if(zRight) {
        char *deprecation = "PRAGMA cipher_hmac_pgno is deprecated, please remove from use";
        /* clear both pgno endian flags */
        if(sqlite3_stricmp(zRight, "le") == 0) {
          SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_BE_PGNO);
          SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_LE_PGNO);
        } else if(sqlite3_stricmp(zRight, "be") == 0) {
          SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_LE_PGNO);
          SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_BE_PGNO);
        } else if(sqlite3_stricmp(zRight, "native") == 0) {
          SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_LE_PGNO);
          SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_BE_PGNO);
        }
        sqlcipher_vdbe_return_string(pParse, "cipher_hmac_pgno", deprecation, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, deprecation);
 
      } else {
        if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_LE_PGNO)) {
          sqlcipher_vdbe_return_string(pParse, "cipher_hmac_pgno", "le", P4_TRANSIENT);
        } else if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_BE_PGNO)) {
          sqlcipher_vdbe_return_string(pParse, "cipher_hmac_pgno", "be", P4_TRANSIENT);
        } else {
          sqlcipher_vdbe_return_string(pParse, "cipher_hmac_pgno", "native", P4_TRANSIENT);
        }
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_salt_mask")==0 ){
    if(ctx) {
      if(zRight) {
        char *deprecation = "PRAGMA cipher_hmac_salt_mask is deprecated, please remove from use";
        if (sqlite3StrNICmp(zRight ,"x'", 2) == 0 && sqlite3Strlen30(zRight) == 5) {
          unsigned char mask = 0;
          const unsigned char *hex = (const unsigned char *)zRight+2;
          cipher_hex2bin(hex,2,&mask);
          hmac_salt_mask = mask;
        }
        sqlcipher_vdbe_return_string(pParse, "cipher_hmac_salt_mask", deprecation, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, deprecation);
      } else {
        char *mask = sqlite3_mprintf("%02x", hmac_salt_mask);
        sqlcipher_vdbe_return_string(pParse, "cipher_hmac_salt_mask", mask, P4_DYNAMIC);
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_plaintext_header_size")==0 ){
    if(ctx) {
      if( zRight ) {
        int size = atoi(zRight);
        /* deliberately ignore result code, if size is invalid it will be set to -1
           and trip the error later in the codec */
        sqlcipher_codec_ctx_set_plaintext_header_size(ctx, size);
      } else {
        char *size = sqlite3_mprintf("%d", ctx->plaintext_header_sz);
        sqlcipher_vdbe_return_string(pParse, "cipher_plaintext_header_size", size, P4_DYNAMIC);
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_plaintext_header_size")==0 ){
    if( zRight ) {
      default_plaintext_header_size = atoi(zRight);
    } else {
      char *size = sqlite3_mprintf("%d", default_plaintext_header_size);
      sqlcipher_vdbe_return_string(pParse, "cipher_default_plaintext_header_size", size, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_salt")==0 ){
    if(ctx) {
      if(zRight) {
        if (sqlite3StrNICmp(zRight ,"x'", 2) == 0 && sqlite3Strlen30(zRight) == (FILE_HEADER_SZ*2)+3) {
          unsigned char *salt = (unsigned char*) sqlite3_malloc(FILE_HEADER_SZ);
          const unsigned char *hex = (const unsigned char *)zRight+2;
          cipher_hex2bin(hex,FILE_HEADER_SZ*2,salt);
          sqlcipher_codec_ctx_set_kdf_salt(ctx, salt, FILE_HEADER_SZ);
          sqlite3_free(salt);
        }
      } else {
        void *salt;
        char *hexsalt = (char*) sqlite3_malloc((FILE_HEADER_SZ*2)+1);
        if((rc = sqlcipher_codec_ctx_get_kdf_salt(ctx, &salt)) == SQLITE_OK) {
          cipher_bin2hex(salt, FILE_HEADER_SZ, hexsalt);
          sqlcipher_vdbe_return_string(pParse, "cipher_salt", hexsalt, P4_DYNAMIC);
        } else {
          sqlite3_free(hexsalt);
          sqlcipher_codec_ctx_set_error(ctx, rc);
        }
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_algorithm")==0 ){
    if(ctx) {
      if(zRight) {
        rc = SQLITE_ERROR;
        if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA1_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA256_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA256);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA512_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
        }
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
      } else {
        int algorithm = ctx->hmac_algorithm;
        if(ctx->hmac_algorithm == SQLCIPHER_HMAC_SHA1) {
          sqlcipher_vdbe_return_string(pParse, "cipher_hmac_algorithm", SQLCIPHER_HMAC_SHA1_LABEL, P4_TRANSIENT);
        } else if(algorithm == SQLCIPHER_HMAC_SHA256) {
          sqlcipher_vdbe_return_string(pParse, "cipher_hmac_algorithm", SQLCIPHER_HMAC_SHA256_LABEL, P4_TRANSIENT);
        } else if(algorithm == SQLCIPHER_HMAC_SHA512) {
          sqlcipher_vdbe_return_string(pParse, "cipher_hmac_algorithm", SQLCIPHER_HMAC_SHA512_LABEL, P4_TRANSIENT);
        }
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_hmac_algorithm")==0 ){
    if(zRight) {
      rc = SQLITE_OK;
      if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA1_LABEL) == 0) {
        default_hmac_algorithm = SQLCIPHER_HMAC_SHA1;
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA256_LABEL) == 0) {
        default_hmac_algorithm = SQLCIPHER_HMAC_SHA256;
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA512_LABEL) == 0) {
        default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
      }
    } else {
      if(default_hmac_algorithm == SQLCIPHER_HMAC_SHA1) {
        sqlcipher_vdbe_return_string(pParse, "cipher_default_hmac_algorithm", SQLCIPHER_HMAC_SHA1_LABEL, P4_TRANSIENT);
      } else if(default_hmac_algorithm == SQLCIPHER_HMAC_SHA256) {
        sqlcipher_vdbe_return_string(pParse, "cipher_default_hmac_algorithm", SQLCIPHER_HMAC_SHA256_LABEL, P4_TRANSIENT);
      } else if(default_hmac_algorithm == SQLCIPHER_HMAC_SHA512) {
        sqlcipher_vdbe_return_string(pParse, "cipher_default_hmac_algorithm", SQLCIPHER_HMAC_SHA512_LABEL, P4_TRANSIENT);
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_kdf_algorithm")==0 ){
    if(ctx) {
      if(zRight) {
        rc = SQLITE_ERROR;
        if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA256);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
        }
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
      } else {
        if(ctx->kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
          sqlcipher_vdbe_return_string(pParse, "cipher_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL, P4_TRANSIENT);
        } else if(ctx->kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
          sqlcipher_vdbe_return_string(pParse, "cipher_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL, P4_TRANSIENT);
        } else if(ctx->kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
          sqlcipher_vdbe_return_string(pParse, "cipher_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL, P4_TRANSIENT);
        }
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_kdf_algorithm")==0 ){
    if(zRight) {
      rc = SQLITE_OK;
      if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL) == 0) {
        default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA1;
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL) == 0) {
        default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA256;
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL) == 0) {
        default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
      }
    } else {
      if(default_kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
        sqlcipher_vdbe_return_string(pParse, "cipher_default_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL, P4_TRANSIENT);
      } else if(default_kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
        sqlcipher_vdbe_return_string(pParse, "cipher_default_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL, P4_TRANSIENT);
      } else if(default_kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
        sqlcipher_vdbe_return_string(pParse, "cipher_default_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL, P4_TRANSIENT);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_compatibility")==0 ){
    if(ctx) {
      if(zRight) {
        int version = atoi(zRight); 

        switch(version) {
          case 1: 
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 4000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 2: 
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 4000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 3:
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 64000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          default:
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 4096);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 256000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;
        }  

        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
      } 
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_compatibility")==0 ){
    if(zRight) {
      int version = atoi(zRight); 
      switch(version) {
        case 1: 
          default_page_size = 1024;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA1;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA1;
          default_kdf_iter = 4000;
          sqlcipher_set_default_use_hmac(0);
          break;

        case 2: 
          default_page_size = 1024;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA1;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA1;
          default_kdf_iter = 4000;
          sqlcipher_set_default_use_hmac(1);
          break;

        case 3:
          default_page_size = 1024;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA1;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA1;
          default_kdf_iter = 64000;
          sqlcipher_set_default_use_hmac(1);
          break;

        default:
          default_page_size = 4096;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
          default_kdf_iter = 256000;
          sqlcipher_set_default_use_hmac(1);
          break;
      }  
    } 
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_memory_security")==0 ){
    if( zRight ) {
      if(sqlite3GetBoolean(zRight,1)) {
        /* memory security can only be enabled, not disabled */
        sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipher_set_mem_security: on");
        sqlcipher_mem_security_on = 1;
      }
    } else {
      /* only report that memory security is enabled if pragma cipher_memory_security is ON and
         SQLCipher's allocator/deallocator was run at least one time */
      int state = sqlcipher_mem_security_on && sqlcipher_mem_executed;
      char *on = sqlite3_mprintf("%d", state);
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE,
        "sqlcipher_get_mem_security: sqlcipher_mem_security_on = %d, sqlcipher_mem_executed = %d", 
        sqlcipher_mem_security_on, sqlcipher_mem_executed);
      sqlcipher_vdbe_return_string(pParse, "cipher_memory_security", on, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_settings")==0 ){
    if(ctx) {
      int algorithm;
      char *pragma;

      pragma = sqlite3_mprintf("PRAGMA kdf_iter = %d;", ctx->kdf_iter);
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_page_size = %d;", ctx->page_sz);
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_use_hmac = %d;", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC));
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_plaintext_header_size = %d;", ctx->plaintext_header_sz);
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      algorithm = ctx->hmac_algorithm;
      pragma = NULL;
      if(algorithm == SQLCIPHER_HMAC_SHA1) {
        pragma = sqlite3_mprintf("PRAGMA cipher_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA1_LABEL);
      } else if(algorithm == SQLCIPHER_HMAC_SHA256) {
        pragma = sqlite3_mprintf("PRAGMA cipher_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA256_LABEL);
      } else if(algorithm == SQLCIPHER_HMAC_SHA512) {
        pragma = sqlite3_mprintf("PRAGMA cipher_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA512_LABEL);
      }
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      algorithm = ctx->kdf_algorithm;
      pragma = NULL;
      if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
        pragma = sqlite3_mprintf("PRAGMA cipher_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL);
      } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
        pragma = sqlite3_mprintf("PRAGMA cipher_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL);
      } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
        pragma = sqlite3_mprintf("PRAGMA cipher_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL);
      }
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_settings")==0 ){
    char *pragma;

    pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_iter = %d;", default_kdf_iter);
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_page_size = %d;", default_page_size);
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_use_hmac = %d;", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC)); 
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_plaintext_header_size = %d;", default_plaintext_header_size);
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = NULL;
    if(default_hmac_algorithm == SQLCIPHER_HMAC_SHA1) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA1_LABEL);
    } else if(default_hmac_algorithm == SQLCIPHER_HMAC_SHA256) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA256_LABEL);
    } else if(default_hmac_algorithm == SQLCIPHER_HMAC_SHA512) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA512_LABEL);
    }
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = NULL;
    if(default_kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL);
    } else if(default_kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL);
    } else if(default_kdf_algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL);
    }
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_integrity_check")==0 ){
    if(ctx) {
      sqlcipher_codec_ctx_integrity_check(ctx, pParse, "cipher_integrity_check");
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_log_level")==0 ){
    if(zRight) {
      sqlcipher_log_level = SQLCIPHER_LOG_NONE;
      if(sqlite3_stricmp(zRight,      "ERROR")==0) sqlcipher_log_level = SQLCIPHER_LOG_ERROR;
      else if(sqlite3_stricmp(zRight, "WARN" )==0) sqlcipher_log_level = SQLCIPHER_LOG_WARN;
      else if(sqlite3_stricmp(zRight, "INFO" )==0) sqlcipher_log_level = SQLCIPHER_LOG_INFO;
      else if(sqlite3_stricmp(zRight, "DEBUG")==0) sqlcipher_log_level = SQLCIPHER_LOG_DEBUG;
      else if(sqlite3_stricmp(zRight, "TRACE")==0) sqlcipher_log_level = SQLCIPHER_LOG_TRACE;
    }
    sqlcipher_vdbe_return_string(pParse, "cipher_log_level", sqlcipher_get_log_level_str(sqlcipher_log_level), P4_TRANSIENT);
  } else
  if( sqlite3_stricmp(zLeft, "cipher_log_source")==0 ){
    if(zRight) {
      if(sqlite3_stricmp(zRight,      "NONE"    )==0) sqlcipher_log_source = SQLCIPHER_LOG_NONE;
      else if(sqlite3_stricmp(zRight, "ANY"     )==0) sqlcipher_log_source = SQLCIPHER_LOG_ANY;
      else {
        if(sqlite3_stricmp(zRight,      "CORE"    )==0) SQLCIPHER_FLAG_SET(sqlcipher_log_source, SQLCIPHER_LOG_CORE);
        else if(sqlite3_stricmp(zRight, "MEMORY"  )==0) SQLCIPHER_FLAG_SET(sqlcipher_log_source, SQLCIPHER_LOG_MEMORY);
        else if(sqlite3_stricmp(zRight, "MUTEX"   )==0) SQLCIPHER_FLAG_SET(sqlcipher_log_source, SQLCIPHER_LOG_MUTEX);
        else if(sqlite3_stricmp(zRight, "PROVIDER")==0) SQLCIPHER_FLAG_SET(sqlcipher_log_source, SQLCIPHER_LOG_PROVIDER);
      }
    }
    sqlcipher_vdbe_return_string(pParse, "cipher_log_source", sqlcipher_get_log_sources_str(sqlcipher_log_source), P4_DYNAMIC);
  } else
  if( sqlite3_stricmp(zLeft, "cipher_log")== 0 && zRight ){
      char *status = sqlite3_mprintf("%d", sqlcipher_set_log(zRight));
      sqlcipher_vdbe_return_string(pParse, "cipher_log", status, P4_DYNAMIC);
  }else {
    return 0;
  }
  return 1;
}

/* these constants are used internally within SQLite's pager.c to differentiate between
   operations on the main database or journal pages. This is important in the context
   of a rekey operations, where the journal must be written using the original key 
   material (to allow a transactional rollback), while the new database pages are being
   written with the new key material*/
#define CODEC_READ_OP 3
#define CODEC_WRITE_OP 6
#define CODEC_JOURNAL_OP 7

/*
 * sqlite3Codec can be called in multiple modes.
 * encrypt mode - expected to return a pointer to the 
 *   encrypted data without altering pData.
 * decrypt mode - expected to return a pointer to pData, with
 *   the data decrypted in the input buffer
 */
static void* sqlite3Codec(void *iCtx, void *data, Pgno pgno, int mode) {
  codec_ctx *ctx = (codec_ctx *) iCtx;
  int offset = 0, rc = 0;
  unsigned char *pData = (unsigned char *) data;
  int cctx = CIPHER_READ_CTX;
  void *out = NULL;
  sqlite3_mutex *mutex = ctx->pBt->sharable ? sqlcipher_mutex(SQLCIPHER_MUTEX_SHAREDCACHE) : NULL;

  /* in shared cache mode, this needs to be mutexed to prevent a separate database handle from
   * nuking the context on the shared Btree */
  if(mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering mutex %p", __func__, mutex);
    sqlite3_mutex_enter(mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered mutex %p", __func__, mutex);
  }

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3Codec: pgno=%d, mode=%d, ctx->page_sz=%d", pgno, mode, ctx->page_sz);

  if(ctx->error != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: identified deferred error condition: %d", __func__, rc);
    sqlcipher_codec_ctx_set_error(ctx, ctx->error);
    goto cleanup;
  }

  /* call to derive keys if not present yet */
  if((rc = sqlcipher_codec_key_derive(ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3Codec: error occurred during key derivation: %d", rc);
    sqlcipher_codec_ctx_set_error(ctx, rc);
    goto cleanup;
  }

  /* if the plaintext_header_size is negative that means an invalid size was set via 
     PRAGMA. We can't set the error state on the pager at that point because the pager
     may not be open yet. However, this is a fatal error state, so abort the codec */
  if(ctx->plaintext_header_sz < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3Codec: error invalid ctx->plaintext_header_sz: %d", ctx->plaintext_header_sz);
    sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
    goto cleanup;
  }

  if(pgno == 1) /* adjust starting pointers in data page for header offset on first page*/   
    offset = ctx->plaintext_header_sz ? ctx->plaintext_header_sz : FILE_HEADER_SZ; 
  

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3Codec: switch mode=%d offset=%d",  mode, offset);
  switch(mode) {
    case CODEC_READ_OP: /* decrypt */
      if(pgno == 1) /* copy initial part of file header or SQLite magic to buffer */ 
        memcpy(ctx->buffer, ctx->plaintext_header_sz ? pData : (void *) SQLITE_FILE_HEADER, offset); 

      rc = sqlcipher_page_cipher(ctx, cctx, pgno, CIPHER_DECRYPT, ctx->page_sz - offset, pData + offset, (unsigned char*)ctx->buffer + offset);
#ifdef SQLCIPHER_TEST
      if((cipher_test_flags & TEST_FAIL_DECRYPT) > 0 && sqlcipher_get_test_fail()) {
        rc = SQLITE_ERROR;
        sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "sqlite3Codec: simulating decryption failure for pgno=%d, mode=%d, ctx->page_sz=%d\n", pgno, mode, ctx->page_sz);
      }
#endif
      if(rc != SQLITE_OK) {
        /* failure to decrypt a page is considered a permanent error and will render the pager unusable
         * in order to prevent inconsistent data being loaded into page cache. The only exception here is when a database is being "recovered",
         * which we consider to be the case if the plaintext header size is set to the full non-reserved size of a page. If that is the case we consider
         * this to be operating in recovery mode, and will log the error but not permanently put the codec into an error state */
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3Codec: error decrypting page %d data: %d", pgno, rc);
        sqlcipher_memset((unsigned char*) ctx->buffer+offset, 0, ctx->page_sz-offset);
        if(ctx->plaintext_header_sz == ctx->page_sz - ctx->reserve_sz) {
          sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: plaintext header size of %d indicates recovery mode, suppressing permanent error", __func__, ctx->plaintext_header_sz);
        } else {
          sqlcipher_codec_ctx_set_error(ctx, rc);
        }
      } else {
        SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_KEY_USED);
      }
      memcpy(pData, ctx->buffer, ctx->page_sz); /* copy buffer data back to pData and return */
      out = pData;
      goto cleanup;
      break;

    case CODEC_WRITE_OP: /* encrypt database page, operate on write context and fall through to case 7, so the write context is used*/
      cctx = CIPHER_WRITE_CTX; 

    case CODEC_JOURNAL_OP: /* encrypt journal page, operate on read context use to get the original page data from the database */ 
      if(pgno == 1) { /* copy initial part of file header or salt to buffer */ 
        void *kdf_salt = NULL; 
        /* retrieve the kdf salt */
        if((rc = sqlcipher_codec_ctx_get_kdf_salt(ctx, &kdf_salt)) != SQLITE_OK) {
          sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3Codec: error retrieving salt: %d", rc);
          sqlcipher_codec_ctx_set_error(ctx, rc); 
          goto cleanup;
        }
        memcpy(ctx->buffer, ctx->plaintext_header_sz ? pData : kdf_salt, offset);
      }
      rc = sqlcipher_page_cipher(ctx, cctx, pgno, CIPHER_ENCRYPT, ctx->page_sz - offset, pData + offset, (unsigned char*)ctx->buffer + offset);
#ifdef SQLCIPHER_TEST
      if((cipher_test_flags & TEST_FAIL_ENCRYPT) > 0 && sqlcipher_get_test_fail()) {
        rc = SQLITE_ERROR;
        sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "sqlite3Codec: simulating encryption failure for pgno=%d, mode=%d, ctx->page_sz=%d\n", pgno, mode, ctx->page_sz);
      }
#endif
      if(rc != SQLITE_OK) {
        /* failure to encrypt a page is considered a permanent error and will render the pager unusable
           in order to prevent corrupted pages from being written to the main databased when using WAL */
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3Codec: error encrypting page %d data: %d", pgno, rc);
        sqlcipher_memset((unsigned char*)ctx->buffer+offset, 0, ctx->page_sz-offset);
        sqlcipher_codec_ctx_set_error(ctx, rc);
        goto cleanup;
      }
      SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_KEY_USED);
      out = ctx->buffer; /* return persistent buffer data, pData remains intact */
      goto cleanup;
      break;

    default:
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3Codec: error unsupported codec mode %d", mode);
      sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR); /* unsupported mode, set error */
      out = pData;
      goto cleanup;
      break;
  }

cleanup:
  if(mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving mutex %p", __func__, mutex);
    sqlite3_mutex_leave(mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left mutex %p", __func__, mutex);
  }
  return out;
}

/* This callback will be invoked when a database connection is closed. It is basically a light wrapper
 * ariund sqlciher_codec_ctx_free that locks the shared cache mutex if necessary */
static void sqlite3FreeCodecArg(void *pCodecArg) {
  codec_ctx *ctx = (codec_ctx *) pCodecArg;
  sqlite3_mutex *mutex = ctx->pBt->sharable ? sqlcipher_mutex(SQLCIPHER_MUTEX_SHAREDCACHE) : NULL;

  if(pCodecArg == NULL) return;

  /* in shared cache mode, this needs to be mutexed to prevent a codec context from being deallocated when
   * it is in use by the codec due to cross-database handle access to the shared Btree */
  if(mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering mutex %p", __func__, mutex);
    sqlite3_mutex_enter(mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered mutex %p", __func__, mutex);
  }

  sqlcipher_codec_ctx_free(&ctx); /* wipe and free allocated memory for the context */

  if(mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving mutex %p", __func__, mutex);
    sqlite3_mutex_leave(mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left mutex %p", __func__, mutex);
  }
}

int sqlcipherCodecAttach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  struct Db *pDb = NULL;
  sqlite3_file *fd = NULL;
  codec_ctx *ctx = NULL;
  Pager *pPager = NULL;
  int rc = SQLITE_OK;
  sqlite3_mutex *extra_mutex = NULL;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p, nDb=%d", __func__, db, nDb);

  if(!sqlcipher_init) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlcipher not initialized %d", __func__, sqlcipher_init_error);
    return sqlcipher_init_error;
  }

  /* error pKey is not null and nKey is > 0 */
  if(!(nKey && zKey)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: no key", __func__);
    return SQLITE_MISUSE;
  }

  if(!(db && (pDb = &db->aDb[nDb]))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: invalid database", __func__);
    return SQLITE_MISUSE;
  }

  /* After this point, early returns for API misuse are complete, lock on a mutex and ensure it is cleaned
   * up later. If shared cache is enabled then enter a specially defined "global" recursive mutex specifically
   * for isolating shared cache connections, otherwise use the built-in databse mutex */ 
  extra_mutex = pDb->pBt->sharable ? sqlcipher_mutex(SQLCIPHER_MUTEX_SHAREDCACHE) : NULL;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering database mutex %p", __func__, db->mutex);
  sqlite3_mutex_enter(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered database mutex %p", __func__, db->mutex);

  if(extra_mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering mutex %p", __func__, extra_mutex);
    sqlite3_mutex_enter(extra_mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered mutex %p", __func__, extra_mutex);
  }

  pPager = sqlite3BtreePager(pDb->pBt);
  ctx = (codec_ctx*) sqlcipherPagerGetCodec(pPager);

  if(ctx != NULL) {
    /* There is already a codec attached to this database */
    if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) {
       /* The key was derived and used successfully, so return early */
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: disregarding attempt to set key on an previously keyed database connection handle", __func__);
      goto cleanup;
#ifndef SQLITE_DEBUG
    } else if (pDb->pBt->sharable) {
      /* This Btree is participating in shared cache. It would be usafe to reset and reattach a new codec, so return early.
       *
       * When compiled with SQLITE_DEBUG, all database connections have shared cached enabled. This behavior of disallowing reset
       * of the codec on a shared cache connection will break several tests that depend on the the ability to reset the codec,
       * like migration tests, repeat-keying tests, etc. Asa result we will disable shared cache handling when compiled with
       * SQLIE_DEBUG enabled.*/
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: disregarding attempt to set key on an shared cache handle", __func__);
      goto cleanup;
#endif
    } else {
      /* To preseve legacy functionality where an incorrect key could be replaced by a correct key without closing the database,
       * if the key has not been used, and shared cache is not enabled, reset the codec on this pager entirely.
       * This will call sqlcipher_codec_ctx_free directly instead of through sqlite3FreeCodecArg because this function already
       * holds the shared cache mutex if it is necessary, and that avoids requiring a more expensive recursive mutex */
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: resetting existing codec on pager", __func__);
      sqlcipher_codec_ctx_free(&ctx);
      sqlcipherPagerSetCodec(pPager, NULL, NULL, NULL, NULL);
      ctx = NULL;
    }
  }

  /* check if the sqlite3_file is open, and if not force handle to NULL */
  if((fd = sqlite3PagerFile(pPager))->pMethods == 0) fd = NULL;

  /* point the internal codec argument against the contet to be prepared */
  rc = sqlcipher_codec_ctx_init(&ctx, pDb, pPager, zKey, nKey);

  if(rc != SQLITE_OK) {
    /* initialization failed, do not attach potentially corrupted context */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: context initialization failed, forcing error state with rc=%d", __func__, rc);
    /* force an error at the pager level, such that even the upstream caller ignores the return code
       the pager will be in an error state and will process no further operations */
    sqlite3pager_error(pPager, rc);
    pDb->pBt->pBt->db->errCode = rc;
    goto cleanup;
  }

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipherPagerSetCodec()", __func__);
  sqlcipherPagerSetCodec(pPager, sqlite3Codec, NULL, sqlite3FreeCodecArg, (void *) ctx);

  codec_set_btree_to_codec_pagesize(db, pDb, ctx);

  /* force secure delete. This has the benefit of wiping internal data when deleted
     and also ensures that all pages are written to disk (i.e. not skipped by
     sqlite3PagerDontWrite optimizations) */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlite3BtreeSecureDelete()", __func__);
  sqlite3BtreeSecureDelete(pDb->pBt, 1);

  /* if fd is null, then this is an in-memory database and
     we dont' want to overwrite the AutoVacuum settings
     if not null, then set to the default */
  if(fd != NULL) {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlite3BtreeSetAutoVacuum()", __func__);
    sqlite3BtreeSetAutoVacuum(pDb->pBt, SQLITE_DEFAULT_AUTOVACUUM);
  }

cleanup:

  if(extra_mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving mutex %p", __func__, extra_mutex);
    sqlite3_mutex_leave(extra_mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left mutex %p", __func__, extra_mutex);
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving database mutex %p", __func__, db->mutex);
  sqlite3_mutex_leave(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left database mutex %p", __func__, db->mutex);

  return rc;
}

int sqlcipher_find_db_index(sqlite3 *db, const char *zDb) {
  int db_index;
  if(zDb == NULL){
    return 0;
  }
  for(db_index = 0; db_index < db->nDb; db_index++) {
    struct Db *pDb = &db->aDb[db_index];
    if(strcmp(pDb->zDbSName, zDb) == 0) {
      return db_index;
    }
  }
  return 0;
}

void sqlite3_activate_see(const char* in) {
  /* do nothing, security enhancements are always active */
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p", __func__, db);
  return sqlite3_key_v2(db, "main", pKey, nKey);
}

int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
  int db_index = sqlcipher_find_db_index(db, zDb);
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p zDb=%s db_index=%d", __func__, db, zDb, db_index);
  return sqlcipherCodecAttach(db, db_index, pKey, nKey);
}

int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3_rekey: db=%p", db);
  return sqlite3_rekey_v2(db, "main", pKey, nKey);
}

/* sqlite3_rekey_v2
** Given a database, this will reencrypt the database using a new key.
** There is only one possible modes of operation - to encrypt a database
** that is already encrpyted. If the database is not already encrypted
** this should do nothing
** The proposed logic for this function follows:
** 1. Determine if the database is already encryptped
** 2. If there is NOT already a key present do nothing
** 3. If there is a key present, re-encrypt the database with the new key
*/
int sqlite3_rekey_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: db=%p zDb=%s", db, zDb);

  if(!sqlcipher_init) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlcipher not initialized %d",__func__, sqlcipher_init_error);
    return sqlcipher_init_error;
  }

  if(db && pKey && nKey) {
    int db_index = sqlcipher_find_db_index(db, zDb);
    struct Db *pDb = &db->aDb[db_index];
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: database zDb=%p db_index:%d", zDb, db_index);
    if(pDb->pBt) {
      codec_ctx *ctx;
      int rc, page_count;
      Pgno pgno;
      PgHdr *page;
      Pager *pPager = sqlite3BtreePager(pDb->pBt);

      ctx = (codec_ctx*) sqlcipherPagerGetCodec(pPager);
     
      if(ctx == NULL) { 
        /* there was no codec attached to this database, so this should do nothing! */ 
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: no codec attached to db %s: rekey can't be used on an unencrypted database", zDb);
        return SQLITE_MISUSE;
      }

      sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "sqlite3_rekey_v2: entering database mutex %p", db->mutex);
      sqlite3_mutex_enter(db->mutex);
      sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "sqlite3_rekey_v2: entered database mutex %p", db->mutex);

      codec_set_pass_key(db, db_index, pKey, nKey, CIPHER_WRITE_CTX);
    
      /* do stuff here to rewrite the database 
      ** 1. Create a transaction on the database
      ** 2. Iterate through each page, reading it and then writing it.
      ** 3. If that goes ok then commit and put ctx->rekey into ctx->key
      **    note: don't deallocate rekey since it may be used in a subsequent iteration 
      */
      rc = sqlite3BtreeBeginTrans(pDb->pBt, 1, 0); /* begin write transaction */
      sqlite3PagerPagecount(pPager, &page_count);
      for(pgno = 1; rc == SQLITE_OK && pgno <= (unsigned int)page_count; pgno++) { /* pgno's start at 1 see pager.c:pagerAcquire */
        if(!sqlite3pager_is_sj_pgno(pPager, pgno)) { /* skip this page (see pager.c:pagerAcquire for reasoning) */
          rc = sqlite3PagerGet(pPager, pgno, &page, 0);
          if(rc == SQLITE_OK) { /* write page see pager_incr_changecounter for example */
            rc = sqlite3PagerWrite(page);
            if(rc == SQLITE_OK) {
              sqlite3PagerUnref(page);
            } else {
             sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: error %d occurred writing page %d", rc, pgno);  
            }
          } else {
             sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: error %d occurred reading page %d", rc, pgno);  
          }
        } 
      }

      /* if commit was successful commit and copy the rekey data to current key, else rollback to release locks */
      if(rc == SQLITE_OK) { 
        sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: committing");
        rc = sqlite3BtreeCommit(pDb->pBt); 
        sqlcipher_codec_key_copy(ctx, CIPHER_WRITE_CTX);
      } else {
        sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: rollback");
        sqlite3BtreeRollback(pDb->pBt, SQLITE_ABORT_ROLLBACK, 0);
      }

      sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "sqlite3_rekey_v2: leaving database mutex %p", db->mutex);
      sqlite3_mutex_leave(db->mutex);
      sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "sqlite3_rekey_v2: left database mutex %p", db->mutex);
    }
    return SQLITE_OK;
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "sqlite3_rekey_v2: no key provided for db %s: rekey can't be used to decrypt an encrypted database", zDb);
  return SQLITE_ERROR;
}

/*
 * Retrieves the current key attached to the database if there is a codec attached to it.
 * The key will be passed back using internally allocated memory and must be freed using
 * sqlcipher_free to avoid memory leaks. If no key is present, zKey will be set to NULL
 * and nKey to 0.
 *
 * If the encryption key has not yet been derived or the key material is stored, it will
 * be passed back directly. Otherwise, a "keyspec" consisting of the raw key and salt
 * will be used instead. */
void sqlcipherCodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey) {
  struct Db *pDb = &db->aDb[nDb];
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "sqlcipherCodecGetKey:db=%p, nDb=%d", db, nDb);
  if( pDb->pBt ) {
    codec_ctx *ctx = (codec_ctx*) sqlcipherPagerGetCodec(sqlite3BtreePager(pDb->pBt));
    
    if(ctx) {
      /* if the key has not been derived yet, or the key is stored (vi PRAGMA cipher_store_pass)
       * then return the key material. Other wise pass back the keyspec */
      if(ctx->read_ctx->derive_key || ctx->store_pass == 1) {
        *zKey = sqlcipher_malloc(ctx->read_ctx->pass_sz);
        *nKey = ctx->read_ctx->pass_sz;
        memcpy(*zKey, ctx->read_ctx->pass, ctx->read_ctx->pass_sz);
      } else {
        sqlcipher_cipher_ctx_get_keyspec(ctx, ctx->read_ctx, (char**) zKey, nKey);
      }
    } else {
      *zKey = NULL;
      *nKey = 0;
    }
  }
}

/*
 * Implementation of an "export" function that allows a caller
 * to duplicate the main database to an attached database. This is intended
 * as a conveneince for users who need to:
 * 
 *   1. migrate from an non-encrypted database to an encrypted database
 *   2. move from an encrypted database to a non-encrypted database
 *   3. convert beween the various flavors of encrypted databases.  
 *
 * This implementation is based heavily on the procedure and code used
 * in vacuum.c, but is exposed as a function that allows export to any
 * named attached database.
 */

/*
** Finalize a prepared statement.  If there was an error, store the
** text of the error message in *pzErrMsg.  Return the result code.
** 
** Based on vacuumFinalize from vacuum.c
*/
static int sqlcipher_finalize(sqlite3 *db, sqlite3_stmt *pStmt, char **pzErrMsg){
  int rc;
  rc = sqlite3VdbeFinalize((Vdbe*)pStmt);
  if( rc ){
    sqlite3SetString(pzErrMsg, db, sqlite3_errmsg(db));
  }
  return rc;
}

/*
** Execute zSql on database db. Return an error code.
** 
** Based on execSql from vacuum.c
*/
static int sqlcipher_execSql(sqlite3 *db, char **pzErrMsg, const char *zSql){
  sqlite3_stmt *pStmt;
  VVA_ONLY( int rc; )
  if( !zSql ){
    return SQLITE_NOMEM;
  }
  if( SQLITE_OK!=sqlite3_prepare(db, zSql, -1, &pStmt, 0) ){
    sqlite3SetString(pzErrMsg, db, sqlite3_errmsg(db));
    return sqlite3_errcode(db);
  }
  VVA_ONLY( rc = ) sqlite3_step(pStmt);
  assert( rc!=SQLITE_ROW );
  return sqlcipher_finalize(db, pStmt, pzErrMsg);
}

/*
** Execute zSql on database db. The statement returns exactly
** one column. Execute this as SQL on the same database.
** 
** Based on execExecSql from vacuum.c
*/
static int sqlcipher_execExecSql(sqlite3 *db, char **pzErrMsg, const char *zSql){
  sqlite3_stmt *pStmt;
  int rc;

  rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
  if( rc!=SQLITE_OK ) return rc;

  while( SQLITE_ROW==sqlite3_step(pStmt) ){
    rc = sqlcipher_execSql(db, pzErrMsg, (char*)sqlite3_column_text(pStmt, 0));
    if( rc!=SQLITE_OK ){
      sqlcipher_finalize(db, pStmt, pzErrMsg);
      return rc;
    }
  }

  return sqlcipher_finalize(db, pStmt, pzErrMsg);
}

/*
 * copy database and schema from the main database to an attached database
 * 
 * Based on sqlite3RunVacuum from vacuum.c
*/
static void sqlcipher_exportFunc(sqlite3_context *context, int argc, sqlite3_value **argv) {
  sqlite3 *db = sqlite3_context_db_handle(context);
  const char* targetDb, *sourceDb; 
  int targetDb_idx = 0;
  u64 saved_flags = db->flags;        /* Saved value of the db->flags */
  u32 saved_mDbFlags = db->mDbFlags;        /* Saved value of the db->mDbFlags */
  int saved_nChange = db->nChange;      /* Saved value of db->nChange */
  int saved_nTotalChange = db->nTotalChange; /* Saved value of db->nTotalChange */
  u8 saved_mTrace = db->mTrace;        /* Saved value of db->mTrace */
  int rc = SQLITE_OK;     /* Return code from service routines */
  char *zSql = NULL;         /* SQL statements */
  char *pzErrMsg = NULL;

  if(argc != 1 && argc != 2) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("invalid number of arguments (%d) passed to sqlcipher_export", argc);
    goto end_of_export;
  }

  if(sqlite3_value_type(argv[0]) == SQLITE_NULL) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("target database can't be NULL");
    goto end_of_export;
  }

  targetDb = (const char*) sqlite3_value_text(argv[0]); 
  sourceDb = "main";

  if(argc == 2) {
    if(sqlite3_value_type(argv[1]) == SQLITE_NULL) {
      rc = SQLITE_ERROR;
      pzErrMsg = sqlite3_mprintf("target database can't be NULL");
      goto end_of_export;
    }
    sourceDb = (char *) sqlite3_value_text(argv[1]);
  }


  /* if the name of the target is not main, but the index returned is zero 
     there is a mismatch and we should not proceed */
  targetDb_idx =  sqlcipher_find_db_index(db, targetDb);
  if(targetDb_idx == 0 && targetDb != NULL && sqlite3_stricmp("main", targetDb) != 0) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("unknown database %s", targetDb);
    goto end_of_export;
  }
  db->init.iDb = targetDb_idx;

  db->flags |= SQLITE_WriteSchema | SQLITE_IgnoreChecks; 
  db->mDbFlags |= DBFLAG_PreferBuiltin | DBFLAG_Vacuum;
  db->flags &= ~(u64)(SQLITE_ForeignKeys | SQLITE_ReverseOrder | SQLITE_Defensive | SQLITE_CountRows); 
  db->mTrace = 0;

  /* Query the schema of the main database. Create a mirror schema
  ** in the temporary database.
  */
  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM %s.sqlite_schema WHERE type='table' AND name!='sqlite_sequence'"
    "   AND rootpage>0"
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM %s.sqlite_schema WHERE sql LIKE 'CREATE INDEX %%' "
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM %s.sqlite_schema WHERE sql LIKE 'CREATE UNIQUE INDEX %%'"
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Loop through the tables in the main database. For each, do
  ** an "INSERT INTO rekey_db.xxx SELECT * FROM main.xxx;" to copy
  ** the contents to the temporary database.
  */
  zSql = sqlite3_mprintf(
    "SELECT 'INSERT INTO %s.' || quote(name) "
    "|| ' SELECT * FROM %s.' || quote(name) || ';'"
    "FROM %s.sqlite_schema "
    "WHERE type = 'table' AND name!='sqlite_sequence' "
    "  AND rootpage>0"
  , targetDb, sourceDb, sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Copy over the contents of the sequence table
  */
  zSql = sqlite3_mprintf(
    "SELECT 'INSERT INTO %s.' || quote(name) "
    "|| ' SELECT * FROM %s.' || quote(name) || ';' "
    "FROM %s.sqlite_schema WHERE name=='sqlite_sequence';"
  , targetDb, sourceDb, targetDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Copy the triggers, views, and virtual tables from the main database
  ** over to the temporary database.  None of these objects has any
  ** associated storage, so all we have to do is copy their entries
  ** from the SQLITE_MASTER table.
  */
  zSql = sqlite3_mprintf(
    "INSERT INTO %s.sqlite_schema "
    "  SELECT type, name, tbl_name, rootpage, sql"
    "    FROM %s.sqlite_schema"
    "   WHERE type='view' OR type='trigger'"
    "      OR (type='table' AND rootpage=0)"
  , targetDb, sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = NULL;
end_of_export:
  db->init.iDb = 0;
  db->flags = saved_flags;
  db->mDbFlags = saved_mDbFlags;
  db->nChange = saved_nChange;
  db->nTotalChange = saved_nTotalChange;
  db->mTrace = saved_mTrace;

  if(zSql) sqlite3_free(zSql);

  if(rc) {
    if(pzErrMsg != NULL) {
      sqlite3_result_error(context, pzErrMsg, -1);
      sqlite3DbFree(db, pzErrMsg);
    } else {
      sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
    }
  }
}
#endif
/* END SQLCIPHER */
