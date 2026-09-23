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
#if !defined(OMIT_SQLCIPHER)

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
#include "btreeInt.h"
#include "pager.h"
#include "vdbeInt.h"

#if !defined(SQLITE_EXTRA_INIT) || !defined(SQLITE_EXTRA_SHUTDOWN)
#error "SQLCipher must be compiled with -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown"
#endif

#if !defined(SQLITE_THREADSAFE) || !(SQLITE_THREADSAFE == 1 || SQLITE_THREADSAFE == 2)
#error "SQLCipher must be compiled with -DSQLITE_THREADSAFE=<1 or 2>"
#endif

/* SQLITE_TEMP_STORE is required to be set at least to 2 which uses memory as the default store. It does allow an application
 * to override it to file at runtime by using PRAGMA temp_store = 1, which could result in temp data to be
 * written to disk. This is an acceptable trade off in case an application with a very large database needs to do some
 * operations requiring temp that would exceed available memory. If we didnt' allow this override the applications would
 * always get SQLITE_NOMEM and ops would fail. For applications that don't care about the ability to override at runtime
 * they can set to 3. Default FILE store is barred outright. */
#if !defined(SQLITE_TEMP_STORE) || SQLITE_TEMP_STORE == 0 || SQLITE_TEMP_STORE == 1
#error "SQLCipher must be compiled with -DSQLITE_TEMP_STORE=<2 or 3>"
#endif

#if !defined(SQLITE_USE_URI) || !(SQLITE_USE_URI == 1)
#error "SQLCipher must be compiled with -DSQLITE_USE_URI"
#endif

/* SQLite defines SQLITE_DIRECT_OVERFLOW_READ default which alloes overflow pages to be read directly fromm disk
 * which bypasses the pager and page cache. This will not work properly with SQLCipher since pages need to be decrypted when read.
 * The SQLCipher VFS already unsets the SQLITE_IOCAP_SUBPAGE_READ flag at runtime in xDeviceCharacteristics to prevent unaligned
 * reads, but requiring this define should eliminate that incompatibility at compile time. */
#if defined(SQLITE_DIRECT_OVERFLOW_READ) && SQLITE_DIRECT_OVERFLOW_READ != 0
#error "SQLCipher must be compiled with -DSQLITE_DIRECT_OVERFLOW_READ=0"
#endif

/* extensions defined in pager.c */ 
int sqlite3pager_is_sj_pgno(Pager*, Pgno);
void sqlite3pager_error(Pager*, int);
void sqlite3pager_reset(Pager *pPager);
sqlite3_file* sqlcipher_pager_sjfd(Pager*);
i64 sqlcipher_pager_journalHdr(Pager*);
u32 sqlcipher_pager_sectorSize(Pager*);
i64 sqlcipher_pager_journalOff(Pager*);
u32 sqlcipher_pager_cksumInit(Pager*);
u32 sqlcipher_pager_wal_salt(Pager *pPager, int);
/* end extensions defined in pager.c */

#if !defined (SQLCIPHER_CRYPTO_CC) \
   && !defined (SQLCIPHER_CRYPTO_LIBTOMCRYPT) \
   && !defined (SQLCIPHER_CRYPTO_OPENSSL) \
   && !defined (SQLCIPHER_CRYPTO_CUSTOM)
#define SQLCIPHER_CRYPTO_OPENSSL
#endif

#define FILE_HEADER_SZ 16

#define CIPHER_XSTR(s) CIPHER_STR(s)
#define CIPHER_STR(s) #s

#ifndef CIPHER_VERSION_NUMBER
#define CIPHER_VERSION_NUMBER 5.0.0-beta
#endif

#ifndef CIPHER_VERSION_BUILD
#define CIPHER_VERSION_BUILD community
#endif

#define CIPHER_READ_CTX 0
#define CIPHER_WRITE_CTX 1
#define CIPHER_READWRITE_CTX 2

#ifndef PBKDF2_ITER
#define PBKDF2_ITER 512000
#endif

#define SQLCIPHER_FLAG_GET(FLAG,BIT) ((FLAG & BIT) != 0)
#define SQLCIPHER_FLAG_SET(FLAG,BIT) FLAG |= BIT
#define SQLCIPHER_FLAG_UNSET(FLAG,BIT) FLAG &= ~BIT

/* possible flags for sqlcipher_ctx->flags */
#define CIPHER_FLAG_HMAC          (1 << 0)
#define CIPHER_FLAG_LE_PGNO       (1 << 1)
#define CIPHER_FLAG_BE_PGNO       (1 << 2)
#define CIPHER_FLAG_KEY_USED      (1 << 3)
#define CIPHER_FLAG_HAS_KDF_SALT  (1 << 4)
#define CIPHER_FLAG_HMAC_FAST_KDF (1 << 5)
#define CIPHER_FLAG_AEAD          (1 << 6)

/* when using AEAD, reserve an additional 12 bytes of
 * random nonce for KBKDF context */
#define SQLCIPHER_KBKDF_CONTEXT_SZ 12

#ifndef DEFAULT_CIPHER_FLAGS
#define DEFAULT_CIPHER_FLAGS (CIPHER_FLAG_AEAD)
#endif


/* SQLCipher versions 4 and below used a reduced number of iterations to generate the hmac key.
 * Starting in SQLCipher 5 this extra KDF operation is disabled in favor of generating the 
 * HMAC key at the same time as the encryption key using an extended length PBKDF2 operation.
 * However, this value will be used in the exception cases, where the version compatibility is < 5
 * or a raw key format is used that does not provide raw key material for the HMAC key. */
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
  unsigned char *subkey;
  unsigned char *cksum_key;
} cipher_ctx;


typedef struct {
  int kdf_iter;
  int kdf_salt_sz;
  int key_sz;
  int iv_sz;
  int block_sz;
  int page_sz;
  int reserve_sz;
  int tag_sz;
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
  unsigned char *page_data;
  int kbkdf_context_sz;
} sqlcipher_ctx;

#ifndef SQLCIPHER_OMIT_MALLOC
typedef struct private_block private_block;
struct private_block {
  private_block *next;
  u32 size;
  u32 is_used;
};
#endif /*SQLCIPHER_OMIT_MALLOC*/

#define SQLCIPHER_DB 0
#define SQLCIPHER_WAL 1
#define SQLCIPHER_JOURNAL 2
#define SQLCIPHER_SUBJOURNAL 3
#define SQLCIPHER_OTHER 4

#define SQLCIPHER_FILE_PASSTHROUGH_READ          (1 << 0)
#define SQLCIPHER_FILE_PASSTHROUGH_WRITE         (1 << 1)

#define SQLCIPHER_WAL_FRAME_HDRSIZE 24 /* Size of header before each frame in wal (from wal.c)*/
#define SQLCIPHER_WAL_HDRSIZE 32 /* Size of write ahead log header, including checksum. (from wal.c) */
#define SQLCIPHER_DB_HDRSIZE 100

typedef struct sqlcipher_file sqlcipher_file;
struct sqlcipher_file {
  sqlite3_file base;
  const char *name;
  char type;
  u32 flags; 
  sqlcipher_file *main;
  sqlcipher_ctx *ctx;
  sqlcipher_file *next;
  int init_error;
  unsigned char header[SQLCIPHER_DB_HDRSIZE];
  unsigned char eheader[SQLCIPHER_DB_HDRSIZE];
};

#ifdef SQLCIPHER_TEST
/* forward definition for the internal selftest function at the end of this file */
void sqlcipher_selftest(sqlite3*, Parse*);
#endif /* SQLCIPHER_TEST */

/* implementation of simple, fast PSRNG function using xoshiro256++ (XOR/shift/rotate)
 * https://prng.di.unimi.it/ under the public domain via https://prng.di.unimi.it/xoshiro256plusplus.c
 * xoshiro is NEVER used for any cryptographic functions as CSPRNG. It is solely used for
 * generating random data for testing, debugging, and forensic purposes (overwriting memory segments).
 * this implementation makes three minor modifications from the stock xoshiro implementation:
 * 1. the xoshiro state is thread local
 * 2. xoshiro_next() checks whether the thread local state has been initialized, and if no
 *    it seeds then
 * 3. the recommended splitmix64 is used based on the thread local state address to seed (rather
 *    than from an strong external source). this is again ok because it is primarily used for fast
 *    anti-forensic spray */

#if defined(_MSC_VER)
static __declspec(thread) volatile uint64_t xoshiro_s[4];
#else
static __thread volatile uint64_t xoshiro_s[4];
#endif

/* splitmix64 is recommended as the seed generator for xoshiro
 * based on public domain implementation at https://prng.di.unimi.it/splitmix64.c */
static uint64_t splitmix64(uint64_t *x) {
  uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static inline uint64_t xoshiro_rotl(const uint64_t x, int k) {
  return (x << k) | (x >> (64 - k));
}

static uint64_t xoshiro_next(void) {
  volatile uint64_t result, t;
  /* if the state has not been initialized (all zeros), seed */
  if(!(xoshiro_s[0] | xoshiro_s[1] | xoshiro_s[2] | xoshiro_s[3])) {
    /* split assignment to a to avoid "relocation truncated to fit: R_X86_64_TPOFF32" error
     * under GCC see issue #600 */
    volatile uintptr_t a_addr = (uintptr_t) &xoshiro_s;
    uint64_t a = (uint64_t) a_addr;
    xoshiro_s[0] = splitmix64(&a);
    xoshiro_s[1] = splitmix64(&a);
    xoshiro_s[2] = splitmix64(&a);
    xoshiro_s[3] = splitmix64(&a);
  }
  result = xoshiro_rotl(xoshiro_s[0] + xoshiro_s[3], 23) + xoshiro_s[0];
  t = xoshiro_s[1] << 17;

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

  if(!ptr) return;

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
#define TEST_FAIL_ENCRYPT        0x01
#define TEST_FAIL_DECRYPT        0x02
#define TEST_FAIL_MIGRATE        0x04
#define TEST_FAIL_REKEY          0x08
#define TEST_FAIL_MIGRATE_CLOSED 0x10

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
static volatile int default_kdf_iter = PBKDF2_ITER;
static volatile int default_page_size = 8192;
static volatile int default_plaintext_header_size = 0;
static volatile int default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
static volatile int default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
static volatile int sqlcipher_mem_security_on = 0;
static volatile int sqlcipher_mem_executed = 0;
static volatile int sqlcipher_mem_initialized = 0;
static volatile sqlite3_mem_methods default_mem_methods;

static sqlcipher_provider *default_provider = NULL;
/* this provider, if set, is allocated by SQLCipher during extra_init
 * and will be freed auotmaticalyl during extra_shutdown */
static sqlcipher_provider *allocd_provider = NULL;

static sqlite3_mutex* sqlcipher_static_mutex[SQLCIPHER_MUTEX_COUNT];

#ifndef SQLCIPHER_LOG_LEVEL_DEFAULT
#define SQLCIPHER_LOG_LEVEL_DEFAULT SQLCIPHER_LOG_WARN
#endif
static FILE* sqlcipher_log_file = NULL;
static volatile int sqlcipher_log_device = 0;
static volatile unsigned int sqlcipher_log_level = SQLCIPHER_LOG_NONE;
static volatile unsigned int sqlcipher_log_source = SQLCIPHER_LOG_ANY;
static volatile int sqlcipher_log_set = 0;

static size_t sqlcipher_shield_mask_sz  = 32;
static u8* sqlcipher_shield_mask = NULL;

#ifndef SQLCIPHER_OMIT_MALLOC
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
static volatile size_t private_heap_used = 0; /* bytes currently used on private heap */
static volatile size_t private_heap_hwm = 0; /* larged number of bytes used on the private heap at one time */
static volatile size_t private_heap_alloc = 0; /* total bytes allocated on private heap over time */
static volatile u32 private_heap_allocs = 0; /* total number of allocations on private heap over time */
static volatile size_t private_heap_overflow = 0; /* total bytes overflowing private heap over time */
static volatile u32 private_heap_overflows = 0; /* number of overlow allocations over time */

/* to prevent excessive fragmentation blocks will
 * only be split if there are at least this many
 * bytes available after the split. This should allow for at
 * least two addtional small allocations */
#define SQLCIPHER_PRIVATE_HEAP_MIN_SPLIT_SIZE 32

/* requested sizes will be rounded up to the nearest 8 bytes for alignment */
#define SQLCIPHER_PRIVATE_HEAP_ALIGNMENT 8
#define SQLCIPHER_PRIVATE_HEAP_ROUNDUP(x) ((x % SQLCIPHER_PRIVATE_HEAP_ALIGNMENT) ? \
  ((x / SQLCIPHER_PRIVATE_HEAP_ALIGNMENT) + 1) * SQLCIPHER_PRIVATE_HEAP_ALIGNMENT : x)
#endif /*SQLCIPHER_OMIT_MALLOC*/

static volatile int sqlcipher_init = 0;
static volatile int sqlcipher_shutdown = 0;
static volatile int sqlcipher_cleanup = 0;
static int sqlcipher_init_error = SQLITE_ERROR;

static void sqlcipher_internal_free(void *, sqlite_uint64);
static void *sqlcipher_internal_malloc(sqlite_uint64);

#define ORIGVFS(p)  ((sqlite3_vfs*)((p)->pAppData))
#define ORIGFILE(p) ((sqlite3_file*)(((sqlcipher_file*)(p))+1))

/* vfs funcs as of v3*/
static int sqlcipherOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);
static int sqlcipherDelete(sqlite3_vfs*, const char *zName, int syncDir);
static int sqlcipherAccess(sqlite3_vfs*, const char *zName, int flags, int *);
static int sqlcipherFullPathname(sqlite3_vfs*, const char *zName, int, char *zOut);
static void *sqlcipherDlOpen(sqlite3_vfs*, const char *zFilename);
static void sqlcipherDlError(sqlite3_vfs*, int nByte, char *zErrMsg);
static void (*sqlcipherDlSym(sqlite3_vfs *pVfs, void *p, const char*zSym))(void);
static void sqlcipherDlClose(sqlite3_vfs*, void*);
static int sqlcipherRandomness(sqlite3_vfs*, int nByte, char *zOut);
static int sqlcipherSleep(sqlite3_vfs*, int microseconds);
static int sqlcipherCurrentTime(sqlite3_vfs*, double*);
static int sqlcipherGetLastError(sqlite3_vfs*, int, char *);
static int sqlcipherCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);
static int sqlcipherSetSystemCall(sqlite3_vfs*, const char*,sqlite3_syscall_ptr);
static sqlite3_syscall_ptr sqlcipherGetSystemCall(sqlite3_vfs*, const char *z);
static const char *sqlcipherNextSystemCall(sqlite3_vfs*, const char *zName);

/* file io funcs */
static int sqlcipherClose(sqlite3_file*);
static int sqlcipherRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int sqlcipherWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64 iOfst);
static int sqlcipherTruncate(sqlite3_file*, sqlite3_int64 size);
static int sqlcipherSync(sqlite3_file*, int flags);
static int sqlcipherFileSize(sqlite3_file*, sqlite3_int64 *pSize);
static int sqlcipherLock(sqlite3_file*, int);
static int sqlcipherUnlock(sqlite3_file*, int);
static int sqlcipherCheckReservedLock(sqlite3_file*, int *pResOut);
static int sqlcipherFileControl(sqlite3_file*, int op, void *pArg);
static int sqlcipherSectorSize(sqlite3_file*);
static int sqlcipherDeviceCharacteristics(sqlite3_file*);
static int sqlcipherShmMap(sqlite3_file*, int iPg, int pgsz, int, void volatile**);
static int sqlcipherShmLock(sqlite3_file*, int offset, int n, int flags);
static void sqlcipherShmBarrier(sqlite3_file*);
static int sqlcipherShmUnmap(sqlite3_file*, int deleteFlag);
static int sqlcipherFetch(sqlite3_file*, sqlite3_int64 iOfst, int iAmt, void **pp);
static int sqlcipherUnfetch(sqlite3_file*, sqlite3_int64 iOfst, void *p);

static sqlite3_vfs sqlcipher_vfs = {
  3, /* iVersion */
  0, /* szOsFile */
  4096, /* mxPathname */
  0, /* pNext */
  "sqlciphervfs", /* zName */
  0, /* pAppData */
  sqlcipherOpen,
  sqlcipherDelete,
  sqlcipherAccess,
  sqlcipherFullPathname,
  sqlcipherDlOpen,
  sqlcipherDlError,
  sqlcipherDlSym,
  sqlcipherDlClose,
  sqlcipherRandomness,
  sqlcipherSleep,
  sqlcipherCurrentTime,
  sqlcipherGetLastError,
  sqlcipherCurrentTimeInt64,
  sqlcipherSetSystemCall,
  sqlcipherGetSystemCall,
  sqlcipherNextSystemCall
};

static const sqlite3_io_methods sqlcipher_io_methods = {
  3, /* iVersion */
  sqlcipherClose,
  sqlcipherRead,
  sqlcipherWrite,
  sqlcipherTruncate,
  sqlcipherSync,
  sqlcipherFileSize,
  sqlcipherLock,
  sqlcipherUnlock,
  sqlcipherCheckReservedLock,
  sqlcipherFileControl,
  sqlcipherSectorSize,
  sqlcipherDeviceCharacteristics,
  sqlcipherShmMap,
  sqlcipherShmLock,
  sqlcipherShmBarrier,
  sqlcipherShmUnmap,
  sqlcipherFetch,
  sqlcipherUnfetch
};

/*
**  Simple shared routines for converting hex char strings to binary data
 */

static int cipher_hex2int(unsigned char c) {
  /* a valid input c can fall into one of three categories. Masks are
   * computed so that the valid type has value 0xFFFFFFFF and the
   * invalid ones are 0x00000000. */
  volatile int mask_d = -((c >= '0') & (c <= '9'));
  volatile int mask_u = -((c >= 'A') & (c <= 'F'));
  volatile int mask_l = -((c >= 'a') & (c <= 'f'));

  /* apply the masks to each value of c adjusted by the appropriate offsets
   * so that only the valid conversion applies. i.e. if c is 'A' then
   * the value 'A' - '0', which is junk just gets masked out to zero. */
  return (mask_d & (c - '0')) | (mask_u & (c - 'A' + 10)) | (mask_l & (c - 'a' + 10));
}

static char cipher_int2hex(int n) {
  volatile int mask = - (n >= 10); /* see mask technique in cipher_hex2int */
  return (char) (
    n + '0' /* map n to ascii */
    + (mask & ('a' - '0' - 10)) /* adjust by offset to lower 'a' if greater than 9 */
  );
}

static void cipher_hex2bin(const unsigned char *hex, int sz, unsigned char *out){
  int i;
  for(i = 0; i < sz; i += 2){
    out[i/2] = (cipher_hex2int(hex[i])<<4) | cipher_hex2int(hex[i+1]);
  }
}

/* this function will write encoded hex from in to out
 * followed by a null terminator. the caller is responsible
 * for ensuring the out buffer is (sz * 2) + 1 bytes. */
static void cipher_bin2hex(const unsigned char* in, int sz, char *out) {
  int i;
  for(i=0; i < sz; i++) {
    out[i*2] = cipher_int2hex(in[i] >> 4);
    out[(i*2)+1] = cipher_int2hex(in[i] & 0x0F);
  } 
  out[sz*2] = '\0'; /* output expected to be zero terminated */
}

static int cipher_isHex(const unsigned char *hex, int sz){
  int i, d, u, l;
  volatile int rc = 1;
  volatile unsigned char c;
  for(i = 0; i < sz; i++) {
    c = hex[i];
    /* check if digit, upper A-F, lower a-f
     * if an input ever fails to fall into one of these groups
     * then clear all bits on rc */
    d = ((c >= '0') & (c <= '9'));
    u = ((c >= 'A') & (c <= 'F'));
    l = ((c >= 'a') & (c <= 'f'));
    rc &= (d | u | l); 
  }
  return rc;
}

sqlite3_mutex* sqlcipher_mutex(int mutex) {
  if(mutex < 0 || mutex >= SQLCIPHER_MUTEX_COUNT) return NULL;
  return sqlcipher_static_mutex[mutex];
}

static void sqlcipher_atexit(void) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipher_extra_shutdown()", __func__);
  sqlcipher_extra_shutdown();
}

static void sqlcipher_fini(void) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipher_extra_shutdown()", __func__);
  sqlcipher_extra_shutdown();
}

#if defined(_WIN32)
  #ifndef SQLCIPHER_OMIT_DLLMAIN
  BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
      case DLL_PROCESS_DETACH:
        sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlcipher_extra_shutdown()", __func__);
        sqlcipher_extra_shutdown();
        break;
      default:
        break;
    }
    return TRUE;
  }
  #endif
#elif defined(__APPLE__)
  #if defined(__has_feature)
    #if __has_feature(address_sanitizer)
    static void sqlcipher_cleanup_destructor(void) __attribute__((destructor));
    static void sqlcipher_cleanup_destructor(void) { sqlcipher_fini(); }
    #else
    static void (*const sqlcipher_fini_func)(void) __attribute__((used, section("__DATA,__mod_term_func"))) = sqlcipher_fini;
    #endif
  #else
    static void (*const sqlcipher_fini_func)(void) __attribute__((used, section("__DATA,__mod_term_func"))) = sqlcipher_fini;
  #endif
#else
static void (*const sqlcipher_fini_func)(void) __attribute__((used, section(".fini_array"))) = sqlcipher_fini;
#endif

static void sqlcipher_exportFunc(sqlite3_context*, int, sqlite3_value**);

static int sqlcipher_export_init(sqlite3* db, char** errmsg, const struct sqlite3_api_routines* api) { 
  sqlite3_create_function_v2(db, "sqlcipher_export", -1, SQLITE_UTF8, 0, sqlcipher_exportFunc, 0, 0, 0);
  return SQLITE_OK;
}

#if defined (SQLCIPHER_CRYPTO_CC)
#define SQLCIPHER_PROVIDER_SETUP sqlcipher_cc_setup 
#elif defined (SQLCIPHER_CRYPTO_LIBTOMCRYPT)
#define SQLCIPHER_PROVIDER_SETUP sqlcipher_ltc_setup 
#elif defined (SQLCIPHER_CRYPTO_OPENSSL)
#define SQLCIPHER_PROVIDER_SETUP sqlcipher_openssl_setup 
#elif defined (SQLCIPHER_CRYPTO_OSSL3)
#define SQLCIPHER_PROVIDER_SETUP sqlcipher_ossl3_setup 
#elif defined (SQLCIPHER_CRYPTO_CUSTOM)
#define SQLCIPHER_PROVIDER_SETUP SQLCIPHER_CRYPTO_CUSTOM
#else
#error "NO DEFAULT SQLCIPHER CRYPTO PROVIDER DEFINED"
#endif


/* The extra_init function is called by sqlite3_init automaticay by virtue of
 * being defined with SQLITE_EXTRA_INIT. This function sets up 
 * static mutexes used internally by SQLCipher and initializes
 * the internal private heap */
int sqlcipher_extra_init(const char* arg) {
  int rc = SQLITE_OK, i=0;
  void* provider_ctx = NULL;
  int mutex_held = 0;

  sqlite3_mutex_enter(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  mutex_held = 1;

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
      sqlcipher_log_level = SQLCIPHER_LOG_LEVEL_DEFAULT;
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

#ifndef SQLCIPHER_OMIT_MALLOC
  /* initialize the private heap for use in internal SQLCipher memory allocations */
  if(private_heap == NULL) {
    while(private_heap_sz >= SQLCIPHER_PRIVATE_HEAP_SIZE_STEP) {
      /* attempt to allocate the private heap. If allocation fails, reduce the size and try again */
      if((private_heap = sqlcipher_internal_malloc(private_heap_sz))) {
        xoshiro_randomness(private_heap, (int) private_heap_sz);
        /* initialize the head block of the linked list at the start of the heap */ 
        private_block *head = (private_block *) private_heap; 
        head->is_used = 0;
        head->size = (u32) private_heap_sz - sizeof(private_block);
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
#endif /*SQLCIPHER_OMIT_MALLOC*/

  /* check to see if there is a provider registered at this point
     if there no provider registered at this point, register the 
     default provider */
  if(sqlcipher_get_provider() == NULL) {
    extern int SQLCIPHER_PROVIDER_SETUP(sqlcipher_provider *);

    if(!(allocd_provider = sqlcipher_malloc(sizeof(sqlcipher_provider)))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to allocate provider", __func__); 
      rc = SQLITE_NOMEM;
      goto error;
    }

    if((rc = SQLCIPHER_PROVIDER_SETUP(allocd_provider)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to setup allocated provider %d", __func__, rc); 
      goto error;
    }

    if((rc = sqlcipher_register_provider(allocd_provider)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register allocated provider %p %d", __func__, allocd_provider, rc); 
      goto error;
    }
  }

  /* required random data */
  if((rc = default_provider->ctx_init(&provider_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to initilize provider context %d", __func__, rc);
    goto error; 
  }
  
  if(default_provider->self_test && (rc = default_provider->self_test(provider_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: default provider self test failed %d", __func__, rc); 
    goto error;
  }

  if((rc = default_provider->random(provider_ctx, (void *)xoshiro_s, sizeof(xoshiro_s))) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to generate xoshiro seed %d", __func__, rc); 
    goto error; 
  }

  if(!sqlcipher_shield_mask) {
    if(!(sqlcipher_shield_mask = sqlcipher_internal_malloc(sqlcipher_shield_mask_sz))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate shield mask", __func__); 
      rc = SQLITE_NOMEM;
      goto error; 
    }
    if((rc = default_provider->random(provider_ctx, sqlcipher_shield_mask, (int) sqlcipher_shield_mask_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to generate requisite random mask data %d", __func__, rc); 
      goto error; 
    }
  }

  default_provider->ctx_free(&provider_ctx);
  provider_ctx = NULL;

  /* leave the master mutex so we can proceed with auto extension registration */
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  mutex_held = 0;

  /* vfs registration must happen out of the mutex, but if this fails it's a permanent error */
  if((rc = sqlcipher_register_vfs()) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed register sqlcipher vfs - fatal error %d", __func__, rc); 
    goto error; 
  }

  /* finally, extension registration occurs outside of the mutex because it is
   * uses SQLITE_MUTEX_STATIC_MASTER itself */
  sqlite3_auto_extension((void (*)(void))sqlcipher_export_init);

  sqlcipher_init = 1;
  sqlcipher_shutdown = 0;

  return SQLITE_OK;
 
error:
  /* if a provider was allocated by SQLCipher and we end up in an error state kill it*/
  if(provider_ctx && default_provider) default_provider->ctx_free(&provider_ctx);

  if(allocd_provider) {
    if(allocd_provider->shutdown) allocd_provider->shutdown();
    if(default_provider == allocd_provider) default_provider = NULL; /* default is ours, clear that ptr */
    sqlcipher_free(allocd_provider, sizeof(sqlcipher_provider));
    allocd_provider = NULL;
  }

  /* if an error occurs during initialization, tear down everything that was setup */
#ifndef SQLCIPHER_OMIT_MALLOC
  if(private_heap) {
    sqlcipher_internal_free(private_heap, private_heap_sz);
    private_heap = NULL;
  }
#endif /*SQLCIPHER_OMIT_MALLOC*/

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
  if(mutex_held) sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
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

  /* if sqlcipher hasn't been initialized or the shutdown already completed exit early */
  if(!sqlcipher_init || sqlcipher_shutdown) {
    goto cleanup;
  }

  if(sqlcipher_shield_mask) {
    sqlcipher_internal_free(sqlcipher_shield_mask, sqlcipher_shield_mask_sz);
    sqlcipher_shield_mask = NULL;
  }

  /* clean up the provider list. start at the default provider and move through the list.
   * 1. if a provider has a shutdown function, call it
   * 2. if the provider is the one that sqlcipher allocated with sqlcipher_malloc in init, free it
   * 3. NULL out the default_provider and allocd_provider */
  provider = default_provider;
  while(provider) {
    sqlcipher_provider *next = provider->next;
    if(provider->shutdown) provider->shutdown(); 
    if(provider == allocd_provider) sqlcipher_free(provider, sizeof(sqlcipher_provider)); 
    provider = next;
  }
  allocd_provider = NULL;
  default_provider = NULL;

  if( sqlite3_vfs_find("sqlciphervfs") ){
    sqlite3_vfs_unregister(&sqlcipher_vfs);
  }

#ifndef SQLCIPHER_OMIT_MALLOC
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
        "%s: SQLCipher private heap unfreed memory %u bytes in %d allocations", __func__, used, i);
    } else {
      sqlcipher_internal_free(private_heap, private_heap_sz);
      private_heap = NULL;
    }
#else
    sqlcipher_internal_free(private_heap, private_heap_sz);
    private_heap = NULL;
#endif
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY,
        "%s: SQLCipher private heap stats: size=%u, hwm=%u, alloc=%u, allocs=%u, overflow=%u, overflows=%u", __func__,
        private_heap_sz, private_heap_hwm, private_heap_alloc, private_heap_allocs, private_heap_overflow, private_heap_overflows
    );
  }
#endif /*SQLCIPHER_OMIT_MALLOC*/

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
}


static void sqlcipher_xor(unsigned char *x, int x_sz, unsigned char *y, int y_sz) {
  int i = 0;
  
  if(x == NULL || y == NULL || x_sz < 1 || y_sz < 1) return;

  for(i = 0; i < x_sz; i++) {
    x[i] ^= y[i % y_sz];
  }
}

static void sqlcipher_shield(unsigned char *in, int sz) {
  sqlcipher_xor(in, sz, sqlcipher_shield_mask, sqlcipher_shield_mask_sz);
}

/* constant time memset using volitile to avoid having the memset
   optimized out by the compiler. 
   Note: As suggested by Joachim Schipper (joachim.schipper@fox-it.com)
*/
void* sqlcipher_memset(void *v, unsigned char value, sqlite_uint64 len) {
  volatile sqlite_uint64 i = 0;
  volatile unsigned char *a = v;

  if (v == NULL) return v;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: setting %p[0-%u]=%d)", __func__, a, len, value);
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

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: calling mlock(%p,%lu); _SC_PAGESIZE=%lu", __func__, ptr - offset, sz + offset, pagesize);
  rc = mlock(ptr - offset, sz + offset);
  if(rc!=0) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: mlock(%p,%lu) returned %d errno=%d", __func__, ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_PC_APP))
  int rc;
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: calling VirtualLock(%p,%d)", __func__, ptr, sz);
  rc = VirtualLock(ptr, sz);
  if(rc==0) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: VirtualLock(%p,%d) returned %d LastError=%d", __func__, ptr, sz, rc, GetLastError());
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

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: calling munlock(%p,%lu)", __func__, ptr - offset, sz + offset);
  rc = munlock(ptr - offset, sz + offset);
  if(rc!=0) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: munlock(%p,%lu) returned %d errno=%d", __func__, ptr - offset, sz + offset, rc, errno);
  }
#elif defined(_WIN32)
#if !(defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP || WINAPI_FAMILY == WINAPI_FAMILY_PC_APP))
  int rc;

  if(ptr == NULL || sz == 0) return;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: calling VirtualUnlock(%p,%d)", __func__, ptr, sz);
  rc = VirtualUnlock(ptr, sz);

  /* because memory allocations may be made from the same individual page, it is possible for VirtualUnlock to be called
   * multiple times for the same page. Subsequent calls will return an error, but this can be safely ignored (i.e. because
   * the previous call for that page unlocked the memory already). Log an info level event only in that case. */
  if(!rc) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: VirtualUnlock(%p,%d) returned %d LastError=%d", __func__, ptr, sz, rc, GetLastError());
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
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s: calling sqlcipher_mlock(%p,%d)", __func__, ptr, n);
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
    if (!p) {
      return sqlcipher_mem_malloc(n);
    }

    orig_sz = sqlcipher_mem_size(p);

    if (n==0) {
      sqlcipher_mem_free(p);
      return NULL;
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
#ifdef SQLCIPHER_OMIT_MALLOC
  free(ptr);
#else
  if(ptr) xoshiro_randomness(ptr, sz);
  sqlcipher_munlock(ptr, sz);
  sqlite3_free(ptr);
#endif /*SQLCIPHER_OMIT_MALLOC*/
}

/**
  * allocate memory. Uses sqlite's internall malloc wrapper so memory can be 
  * reference counted and leak detection works. Unless compiled with OMIT_MEMLOCK
  * attempts to lock the memory pages so sensitive information won't be swapped
  */
static void* sqlcipher_internal_malloc(sqlite_uint64 sz) {
  void *ptr;
#ifdef SQLCIPHER_OMIT_MALLOC
  ptr = malloc(sz);
#else
  ptr = sqlite3_malloc64(sz);
  if(ptr) sqlcipher_mlock(ptr, sz);
#endif /*SQLCIPHER_OMIT_MALLOC*/
  if(ptr) sqlcipher_memset(ptr, 0, sz);
  return ptr;
}

void *sqlcipher_malloc(sqlite3_uint64 size) {
  void *alloc = NULL;
#ifdef SQLCIPHER_OMIT_MALLOC
  alloc = malloc(size);
  if(alloc) sqlcipher_memset(alloc, 0, size);
#else
  private_block *block = NULL, *split = NULL;
  size_t alloc_sz = 0;

  if(size < 1 || size > SQLITE_MAX_LENGTH) return NULL;

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

      alloc_sz = block->size; /* store the actual allocation here, consistent regardless of whether or not a split occurred */
    }
    block = block->next;
  }

  /* If we were unable to locate a free block large enough to service the request, the fallback
     behavior will simply attempt to allocate additional memory using malloc. */
  if(alloc == NULL) {
    private_heap_overflow += size;
    private_heap_overflows++;
    alloc = sqlcipher_internal_malloc(size);
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: unable to allocate %u bytes on private heap, allocated %p using sqlcipher_internal_malloc fallback", __func__, size, alloc);
  } else {
    private_heap_used += alloc_sz;
    if(private_heap_used > private_heap_hwm) {
      /* if the current bytes allocated on the private heap are greater than the high water mark, set the HWM to the new amount */
      private_heap_hwm = private_heap_used;
    }
    private_heap_alloc += alloc_sz;
    private_heap_allocs++;
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s allocated %llu bytes (%u used) on private heap at %p", __func__, size, alloc_sz, alloc);
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_MEM", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_MEM));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_MEM", __func__);
#endif /*SQLCIPHER_OMIT_MALLOC*/
  return alloc;
}

void sqlcipher_free(void *mem, sqlite3_uint64 sz) {
#ifdef SQLCIPHER_OMIT_MALLOC
  free(mem);
#else
  private_block *block = NULL, *prev = NULL;
  void *alloc = NULL;
  u32 block_size = 0;
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
      block_size = block->size; /* retain the acual size of the block in use for stats adjustment */
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

  /* If the memory address couldn't be found in the private heap
     then it was allocated by the fallback mechanism and should
     be deallocated with free() */
  if(!block) {
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_MEMORY, "%s: unable to find %p with %u bytes on private heap, calling sqlcipher_internal_free fallback", __func__, mem, sz);
    sqlcipher_internal_free(mem, sz);
  } else {
    private_heap_used -= block_size;
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MEMORY, "%s freed %u bytes (%u total) on private heap at %p", __func__, sz, block_size, mem);
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_MEM", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_MEM));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_MEM", __func__);
#endif /*SQLCIPHER_OMIT_MALLOC*/
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
  * Free and wipe memory associated with a cipher_ctx
  */
static void sqlcipher_cipher_ctx_free(sqlcipher_ctx* ctx, cipher_ctx **iCtx) {
  cipher_ctx *c_ctx = *iCtx;

  if(!c_ctx) return;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "%s: iCtx=%p", __func__, iCtx);
  if(c_ctx->key) sqlcipher_free(c_ctx->key, ctx->key_sz * 2); /* free encryption and MAC key together */
  if(c_ctx->pass) sqlcipher_free(c_ctx->pass, c_ctx->pass_sz);
  if(c_ctx->subkey) sqlcipher_free(c_ctx->subkey, ctx->key_sz);
  if(c_ctx->cksum_key) sqlcipher_free(c_ctx->cksum_key, ctx->key_sz);
  sqlcipher_free(c_ctx, sizeof(cipher_ctx));
  *iCtx = NULL;
}

/**
  * Initialize new cipher_ctx struct. This function will allocate memory
  * for the cipher context and for the key
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_init(sqlcipher_ctx *ctx, cipher_ctx **iCtx) {
  cipher_ctx *c_ctx = NULL;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "%s: allocating context", __func__);
  if(!(*iCtx = (cipher_ctx *) sqlcipher_malloc(sizeof(cipher_ctx)))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate context", __func__);
    goto error;
  }
 
  c_ctx = *iCtx;

  /* key will point to a memory allocation which is key_sz * 2 bytes long. the first half is the
     encryption key, the second half will be the hmac key */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "%s: allocating key", __func__);
  if(!(c_ctx->key = (unsigned char *) sqlcipher_malloc(ctx->key_sz * 2))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate key", __func__);
    goto error;
  }

  /* for convenience maintain a separate pointer to the hmac_key pointing to the midpoint of the key allocation */
  c_ctx->hmac_key = c_ctx->key + ctx->key_sz;

  /* subkey to be used with AEAD */
  if(!(c_ctx->subkey = (unsigned char *) sqlcipher_malloc(ctx->key_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate subkey", __func__);
    goto error;
  }

  /* key to be used for checksum shielding */
  if(!(c_ctx->cksum_key = (unsigned char *) sqlcipher_malloc(ctx->key_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate cksum_key", __func__);
    goto error;
  }

  return SQLITE_OK;

error:
  if(c_ctx) sqlcipher_cipher_ctx_free(ctx, iCtx);
  return SQLITE_NOMEM;
}

static int sqlcipher_ctx_reserve_setup(sqlcipher_ctx *ctx) {
  int reserve = 0;

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_AEAD)) {
    if(!ctx->provider->aead_kbkdf || !ctx->provider->aead_cipher || !ctx->provider->get_aead_iv_sz  
       || !ctx->provider->get_aead_cipher || !ctx->provider->get_aead_tag_sz) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: provider does not support required AEAD functions", __func__ );
      return SQLITE_ERROR;
    }

    ctx->tag_sz = ctx->provider->get_aead_tag_sz(ctx->provider_ctx); 
    ctx->iv_sz = ctx->provider->get_aead_iv_sz(ctx->provider_ctx);
    ctx->kbkdf_context_sz = SQLCIPHER_KBKDF_CONTEXT_SZ;
  } else if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC)) {
    ctx->tag_sz = ctx->provider->get_hmac_sz(ctx->provider_ctx, ctx->hmac_algorithm); 
    ctx->iv_sz = ctx->provider->get_iv_sz(ctx->provider_ctx);
    ctx->kbkdf_context_sz = 0;
  } else {
    ctx->tag_sz = 0;
    ctx->iv_sz = ctx->provider->get_iv_sz(ctx->provider_ctx);
    ctx->kbkdf_context_sz = 0;
  } 
 
  reserve = ctx->iv_sz + ctx->tag_sz + ctx->kbkdf_context_sz; /* if reserve will include AEAD OR HMAC, update that size */

  /* calculate the amount of reserve needed in even increments of the cipher block size */
  if(ctx->block_sz > 0) {
    reserve = ((reserve % ctx->block_sz) == 0) ? reserve :
               ((reserve / ctx->block_sz) + 1) * ctx->block_sz;  
  }

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: block_sz=%d iv_sz=%d tag_sz=%d kbkdf_context_sz=%d reserve=%d", 
                __func__, ctx->block_sz, ctx->iv_sz, ctx->tag_sz, ctx->kbkdf_context_sz, reserve); 

  ctx->reserve_sz = reserve;

  return SQLITE_OK;
}

/**
  * Compare one cipher_ctx to another.
  *
  * returns 0 if the input key material in the contexts' pass variables are not NULL and matching
  * returns 1 otherwise
  */
static int sqlcipher_cipher_ctx_pass_cmp(cipher_ctx *c1, cipher_ctx *c2) {
  int pass_eq;
  if(c1->pass_sz != c2->pass_sz) { /* pass sizes must match */ 
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_CORE, "%s: context pass_sz mismatch", __func__);
    return 1; 
  }
  if(!c1->pass || !c2->pass) { /* neither pass may be NULL */ 
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_CORE, "%s: context pass is NULL", __func__);
    return 1;
  }
  pass_eq = sqlcipher_memcmp((const unsigned char*)c1->pass, (const unsigned char*)c2->pass, c1->pass_sz);  
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_CORE, "%s: context pass memcmp=%d", __func__, pass_eq);
  return pass_eq;
}

/**
  * Copy one cipher_ctx to another. For instance, assuming that read_ctx is a 
  * fully initialized context, you could copy it to write_ctx and all yet data
  * and pass information across
  *
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int sqlcipher_cipher_ctx_copy(sqlcipher_ctx *ctx, cipher_ctx *target, cipher_ctx *source) {
  void *key = target->key; 
  void *hmac_key = target->hmac_key;
  void *subkey = target->subkey;
  void *cksum_key = target->cksum_key;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: target=%p, source=%p", __func__, target, source);
  if(target->pass) sqlcipher_free(target->pass, target->pass_sz);
  memcpy(target, source, sizeof(cipher_ctx));

  target->key = key; /* restore pointer to previously allocated key data */
  target->hmac_key = hmac_key; /* restore pointer to previously allocated hmac key data */
  memcpy(target->key, source->key, ctx->key_sz * 2); /* copy encryption key and hmac key */

  target->cksum_key = cksum_key; /* restore checksum key pointers */
  memcpy(target->cksum_key, source->cksum_key, ctx->key_sz);

  target->subkey = subkey; /* restore subkey pointers */

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
static int sqlcipher_cipher_ctx_get_keyspec(sqlcipher_ctx *ctx, cipher_ctx *c_ctx, char **keyspec_ptr, int *keyspec_sz) {
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
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC)) { /* if HMAC is enabled, encode key, hmac key, and salt */
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

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC)) {
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

static void sqlcipher_set_derive_key(sqlcipher_ctx *ctx, int derive) {
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

  if(zKey && nKey > 0) { /* if new password is provided, copy it */
    ctx->pass_sz = nKey;
    ctx->pass = sqlcipher_malloc(nKey);
    if(ctx->pass == NULL) return SQLITE_NOMEM;
    memcpy(ctx->pass, zKey, nKey);
  } 
  return SQLITE_OK;
}

static int sqlcipher_ctx_set_pass(sqlcipher_ctx *ctx, const void *zKey, int nKey, int for_ctx) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  int rc;

  if((rc = sqlcipher_cipher_ctx_set_pass(c_ctx, zKey, nKey)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d from sqlcipher_cipher_ctx_set_pass", __func__, rc);
    return rc;
  }

  c_ctx->derive_key = 1;

  if(for_ctx == 2) {
    if((rc = sqlcipher_cipher_ctx_copy(ctx, for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d from sqlcipher_cipher_ctx_copy", __func__, rc);
      return rc;
    }
  }

  return SQLITE_OK;
} 

static int sqlcipher_ctx_set_kdf_iter(sqlcipher_ctx *ctx, int kdf_iter) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;
  ctx->kdf_iter = kdf_iter;
  sqlcipher_set_derive_key(ctx, 1);
  return SQLITE_OK;
}

/* set the global default flag for AEAD */
static void sqlcipher_set_default_aead(int use) {
  if(use) {
    /* AEAD and HMAC are mutually exclusive */
    SQLCIPHER_FLAG_SET(default_flags, CIPHER_FLAG_AEAD);
    SQLCIPHER_FLAG_UNSET(default_flags, CIPHER_FLAG_HMAC);
    SQLCIPHER_FLAG_UNSET(default_flags, CIPHER_FLAG_HMAC_FAST_KDF);
  } else SQLCIPHER_FLAG_UNSET(default_flags,CIPHER_FLAG_AEAD);
}

/* set the flag for whether this individual database should be using AEAD */
static int sqlcipher_ctx_set_aead(sqlcipher_ctx *ctx, int use) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(use) {
    /* AEAD and HMAC are mutually exclusive */
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_AEAD); 
    SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_HMAC);
    SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_HMAC_FAST_KDF);
  } else SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_AEAD); 

  return sqlcipher_ctx_reserve_setup(ctx);
}

/* set the global default flag for HMAC */
static void sqlcipher_set_default_use_hmac(int use) {
  if(use) {
    /* AEAD and HMAC are mutually exclusive */
    SQLCIPHER_FLAG_SET(default_flags, CIPHER_FLAG_HMAC);
    SQLCIPHER_FLAG_UNSET(default_flags, CIPHER_FLAG_AEAD);
  } else SQLCIPHER_FLAG_UNSET(default_flags,CIPHER_FLAG_HMAC);
}

/* set the flag for whether this individual database should be using hmac */
static int sqlcipher_ctx_set_use_hmac(sqlcipher_ctx *ctx, int use) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(use) {
    /* AEAD and HMAC are mutually exclusive */
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HMAC); 
    SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_AEAD); 
  } else SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_HMAC); 

  return sqlcipher_ctx_reserve_setup(ctx);
}

/* set the global default flag for HMAC Fast KDF  */
static void sqlcipher_set_default_hmac_fast_kdf(int use) {
  if(use) {
    /* HMAC is a prerequisite for HMAC_FAST_KDF */
    SQLCIPHER_FLAG_SET(default_flags, CIPHER_FLAG_HMAC);
    SQLCIPHER_FLAG_SET(default_flags, CIPHER_FLAG_HMAC_FAST_KDF);
  } else SQLCIPHER_FLAG_UNSET(default_flags,CIPHER_FLAG_HMAC_FAST_KDF);
}

static int sqlcipher_ctx_set_hmac_fast_kdf(sqlcipher_ctx *ctx, int use) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(use) {
    /* HMAC is a prerequisite for HMAC_FAST_KDF */
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HMAC); 
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HMAC_FAST_KDF); 
  } else SQLCIPHER_FLAG_UNSET(ctx->flags, CIPHER_FLAG_HMAC_FAST_KDF);

  sqlcipher_set_derive_key(ctx, 1);
  return SQLITE_OK;
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
static int sqlcipher_ctx_set_plaintext_header_size(sqlcipher_ctx *ctx, int size) {
  if(size >= 0 && ctx->block_sz > 0 && (size % ctx->block_sz) == 0 && size <= (ctx->page_sz - ctx->reserve_sz)) {
    ctx->plaintext_header_sz = size;
    return SQLITE_OK;
  }
  ctx->plaintext_header_sz = -1;
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: attempt to set invalid plantext_header_size %d", __func__, size);
  return SQLITE_ERROR;
} 

static int sqlcipher_ctx_set_hmac_algorithm(sqlcipher_ctx *ctx, int algorithm) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  ctx->hmac_algorithm = algorithm;
  return sqlcipher_ctx_reserve_setup(ctx);
} 

static int sqlcipher_ctx_set_kdf_algorithm(sqlcipher_ctx *ctx, int algorithm) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  ctx->kdf_algorithm = algorithm;
  return SQLITE_OK;
} 

static void sqlcipher_ctx_set_error(sqlcipher_ctx *ctx, int error) {
  int lock = ctx->pBt->sharable && sqlite3BtreeConnectionCount(ctx->pBt) > 0; /* see btree.c:sqlite3BtreeClose for teardown where mutex is released */
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: %d lock=%d", __func__, error, lock);
  if(lock) sqlite3BtreeEnter(ctx->pBt);
  if(ctx->pBt->pBt->inTransaction != TRANS_WRITE) {
    ctx->pBt->pBt->btsFlags |= BTS_READ_ONLY;
  }
  ctx->pBt->pBt->db->errCode = error;
  if(lock) sqlite3BtreeLeave(ctx->pBt);
  ctx->error = error;
}

static int sqlcipher_ctx_init_kdf_salt(sqlcipher_ctx *ctx) {
  sqlite3_file *fd = sqlite3PagerFile(sqlite3BtreePager(ctx->pBt));
  int rc;

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT)) {
    return SQLITE_OK; /* don't reload salt when not needed */
  }

  /* read salt from header, if present, otherwise generate a new random salt */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: obtaining salt", __func__);
  if(fd == NULL || fd->pMethods == 0 || sqlite3OsRead(fd, ctx->kdf_salt, ctx->kdf_salt_sz, 0) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: unable to read salt from file header, generating random", __func__);
    if((rc = ctx->provider->random(ctx->provider_ctx, ctx->kdf_salt, ctx->kdf_salt_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d retrieving random bytes from provider", __func__, rc);
      return rc;
    }
  }
  SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT);
  return SQLITE_OK; 
}

static int sqlcipher_ctx_set_kdf_salt(sqlcipher_ctx *ctx, unsigned char *salt, int size) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(size >= ctx->kdf_salt_sz) {
    memcpy(ctx->kdf_salt, salt, ctx->kdf_salt_sz);
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT);
    return SQLITE_OK;
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: attempt to set salt of incorrect size %d", __func__, size);
  return SQLITE_ERROR;
}

static int sqlcipher_ctx_get_kdf_salt(sqlcipher_ctx *ctx, void** salt) {
  int rc = SQLITE_OK;
  if(!SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT)) {
    if((rc = sqlcipher_ctx_init_kdf_salt(ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d from sqlcipher_ctx_init_kdf_salt", __func__, rc);
    }
  }
  *salt = ctx->kdf_salt;

  return rc;
}

static int sqlcipher_ctx_set_pagesize(sqlcipher_ctx *ctx, int size) {
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) return SQLITE_OK;

  if(!((size != 0) && ((size & (size - 1)) == 0)) || size < 512 || size > 65536) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "cipher_page_size not a power of 2 and between 512 and 65536 inclusive");
    return SQLITE_ERROR;
  }

  /* attempt to free the existing page buffer */
  if(ctx->buffer) {
    sqlcipher_free(ctx->buffer,ctx->page_sz);
    ctx->buffer = NULL;
  }
  if(ctx->page_data) {
    sqlcipher_free(ctx->page_data,ctx->page_sz);
    ctx->page_data = NULL;
  }

  ctx->page_sz = size;

  /* pre-allocate a page buffer of PageSize bytes. This will
     be used as a persistent buffer for encryption and decryption 
     operations to avoid overhead of multiple memory allocations*/
  if(!(ctx->buffer = sqlcipher_malloc(size))) return SQLITE_NOMEM;
  if(!(ctx->page_data= sqlcipher_malloc(size))) return SQLITE_NOMEM;

  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx, including the allocated
  * read_ctx and write_ctx.
  */
static void sqlcipher_ctx_free(sqlcipher_ctx **iCtx) {
  sqlcipher_ctx *ctx = *iCtx;

  if(!ctx) return;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_MEMORY, "%s: iCtx=%p", __func__, iCtx);
  if(ctx->kdf_salt) sqlcipher_free(ctx->kdf_salt, ctx->kdf_salt_sz);
  if(ctx->hmac_kdf_salt) sqlcipher_free(ctx->hmac_kdf_salt, ctx->kdf_salt_sz);
  if(ctx->buffer) sqlcipher_free(ctx->buffer, ctx->page_sz);
  if(ctx->page_data) sqlcipher_free(ctx->page_data, ctx->page_sz);
  if(ctx->provider) ctx->provider->ctx_free(&ctx->provider_ctx);

  if(ctx->read_ctx) sqlcipher_cipher_ctx_free(ctx, &ctx->read_ctx);
  if(ctx->write_ctx) sqlcipher_cipher_ctx_free(ctx, &ctx->write_ctx);
  sqlcipher_free(ctx, sizeof(sqlcipher_ctx)); 
  *iCtx = NULL;
}

static int sqlcipher_ctx_init(sqlcipher_ctx **iCtx, Db *pDb, const void *zKey, int nKey) {
  int rc = SQLITE_OK;
  sqlcipher_ctx *ctx;

  if(!(*iCtx = sqlcipher_malloc(sizeof(sqlcipher_ctx)))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate context", __func__);
    rc = SQLITE_NOMEM;
    goto error;
  }

  ctx = *iCtx;

  ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */

  /* allocate space for salt data. Then read the first 16 bytes 
       directly off the database file. This is the salt for the
       key derivation function. If we get a short read allocate
       a new random salt value */
  ctx->kdf_salt_sz = FILE_HEADER_SZ;
  if(!(ctx->kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate kdf salt", __func__);
    rc = SQLITE_NOMEM;
    goto error;
  }

  /* allocate space for separate hmac salt data. We want the
     HMAC derivation salt to be different than the encryption
     key derivation salt */
  if(!(ctx->hmac_kdf_salt = sqlcipher_malloc(ctx->kdf_salt_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to allocate hmac kdf salt", __func__);
    rc = SQLITE_NOMEM;
    goto error;
  }

  /* setup default flags */
  ctx->flags = default_flags;

  /* the context will use the current default crypto provider  */
  ctx->provider = default_provider;

  if((rc = ctx->provider->ctx_init(&ctx->provider_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d returned from provider ctx_init", __func__, rc);
    goto error;
  }

  ctx->key_sz = ctx->provider->get_key_sz(ctx->provider_ctx);
  ctx->block_sz = ctx->provider->get_block_sz(ctx->provider_ctx);

  /*
     Always overwrite page size and set to the default because the first page of the database
     in encrypted and thus sqlite can't effectively determine the pagesize. this causes an issue in 
     cases where bytes 16 & 17 of the page header are a power of 2 as reported by John Lehman
  */
  if((rc = sqlcipher_ctx_set_pagesize(ctx, default_page_size)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d returned from sqlcipher_ctx_set_pagesize with %d", __func__, rc, default_page_size);
    goto error;
  }

  /* establish settings for the KDF iterations and fast (HMAC) KDF iterations */
  if((rc = sqlcipher_ctx_set_kdf_iter(ctx, default_kdf_iter)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting default_kdf_iter %d", __func__, rc, default_kdf_iter);
    goto error;
  }

  /* set the default HMAC and KDF algorithms which will determine the reserve size */
  if((rc = sqlcipher_ctx_set_hmac_algorithm(ctx, default_hmac_algorithm)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting sqlcipher_ctx_set_hmac_algorithm with %d", __func__, rc, default_hmac_algorithm);
    goto error;
  }

  /* AEAD is a special case that requires recalculation of page size */
  if((rc = sqlcipher_ctx_set_aead(ctx, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_AEAD))) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting aead %d", __func__, rc, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_AEAD));
    goto error;
  }

  /* HMAC is a special case that requires recalculation of page size so we call set_use_hmac to perform setup */ 
  if((rc = sqlcipher_ctx_set_use_hmac(ctx, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC))) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting use_hmac %d", __func__, rc, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC));
    goto error;
  }

  if((rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC_FAST_KDF))) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting hmac_fast_kdf %d", __func__, rc, SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC_FAST_KDF));
    goto error;
  }

  if((rc = sqlcipher_ctx_set_kdf_algorithm(ctx, default_kdf_algorithm)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting sqlcipher_ctx_set_kdf_algorithm with %d", __func__, rc, default_kdf_algorithm);
    goto error;
  }

  /* setup the default plaintext header size */
  if((rc = sqlcipher_ctx_set_plaintext_header_size(ctx, default_plaintext_header_size)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting sqlcipher_ctx_set_plaintext_header_size with %d", __func__, rc, default_plaintext_header_size);
    goto error;
  }

  /* initialize the read and write sub-contexts. this must happen after key_sz is established  */
  if((rc = sqlcipher_cipher_ctx_init(ctx, &ctx->read_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d initializing read_ctx", __func__, rc);
    goto error;
  } 

  if((rc = sqlcipher_cipher_ctx_init(ctx, &ctx->write_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d initializing write_ctx", __func__, rc);
    goto error;
  }

  /* set the key material on one of the sub cipher contexts and sync them up */
  if((rc = sqlcipher_ctx_set_pass(ctx, zKey, nKey, 0)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d setting pass key", __func__, rc);
    goto error;
  }

  if((rc = sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d copying write_ctx to read_ctx", __func__, rc);
    goto error;
  }

  return SQLITE_OK;

error:
  if(*iCtx) sqlcipher_ctx_free(iCtx);
  return rc;
}

/** convert a 32bit unsigned integer to little endian byte ordering */
static void sqlcipher_put4byte_le(unsigned char *p, u32 v) { 
  p[0] = (u8)v;
  p[1] = (u8)(v>>8);
  p[2] = (u8)(v>>16);
  p[3] = (u8)(v>>24);
}

static int sqlcipher_page_hmac(sqlcipher_ctx *ctx, cipher_ctx *c_ctx, Pgno pgno, unsigned char *in, int in_sz, unsigned char *out) {
  unsigned char pgno_raw[sizeof(pgno)];
  int rc;
  /* we may convert page number to consistent representation before calculating MAC for
     compatibility across big-endian and little-endian platforms. 

     Note: The public release of sqlcipher 2.0.0 to 2.0.6 had a bug where the bytes of pgno 
     were used directly in the MAC. SQLCipher convert's to little endian by default to preserve
     backwards compatibility on the most popular platforms, but can optionally be configured
     to use either big endian or native byte ordering via pragma.

     Update: as of SQLCipher 5 use of the page number is LE. This has been the default for almost 15 years, and
     is no longer editabel */

    sqlcipher_put4byte_le(pgno_raw, pgno);

  /* include the encrypted page data,  initialization vector, and page number in HMAC. This will 
     prevent both tampering with the ciphertext, manipulation of the IV, or resequencing otherwise
     valid pages out of order in a database */ 
  sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);
  rc = ctx->provider->hmac(
    ctx->provider_ctx, ctx->hmac_algorithm, c_ctx->hmac_key,
    ctx->key_sz, in,
    in_sz, (unsigned char*) &pgno_raw,
    sizeof(pgno_raw), out);
  sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);

  return rc;
}

/*
 * ctx - sqlcipher context
 * pgno - page number in database
 * size - size in bytes of input and output buffers
 * mode - 1 to encrypt, 0 to decrypt
 * in - pointer to input bytes
 * out - pouter to output bytes
 */
static int sqlcipher_page_cipher(sqlcipher_ctx *ctx, int for_ctx, Pgno pgno, int mode, int page_sz, unsigned char *in, unsigned char *out) {
  cipher_ctx *c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  unsigned char *reserve_in, *reserve_out, *kbkdf_context_out, *iv_out, *tag_in, *tag_out, *out_start;
  unsigned char pgno_raw[sizeof(pgno)];
  int size, rc;

  size = page_sz - ctx->reserve_sz;

  /* if the full amount of the first page (excluding reserve size), e.g. 4016 bytes for a 4096 byte page size with HMAC_SHA512,
   * is used as a plaintext header, then the entire first page will be completely plaintext, and this function should just return early.
   * This should almost never occur during normal usage, so we will log at WARN level, but it is required in the special case that
   * a user wants to attempt recovery on an encrypted database. In that case, the database header must be completely plaintext so that
   * the recovery VFS can be used with it's special 1st page logic */
  if(pgno == 1 && size == 0) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: skipping encryption/decryption for fully  plaintext header", __func__);
    return SQLITE_OK;
  }

  /* the key size should never be zero. If it is, error out. */
  if(ctx->key_sz == 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error possible context corruption, key_sz is zero for pgno=%d", __func__, pgno);
    rc = SQLITE_MISUSE;
    goto error;
  } 

  /* calculate some required positions into various buffers */
  reserve_out = out + size;
  kbkdf_context_out = reserve_out;
  iv_out = reserve_out + ctx->kbkdf_context_sz;

  reserve_in = in + size;

  /* tag will be written immediately after the kbkdf context and initialization vector. the remainder of the page reserve will contain
     random bytes. note, these pointers are only valid when using aead or hmac */
  tag_in = in + size + ctx->kbkdf_context_sz + ctx->iv_sz; 
  tag_out = out + size + ctx->kbkdf_context_sz + ctx->iv_sz;

  out_start = out; /* note the original position of the output buffer pointer, as out will be rewritten during encryption */

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: pgno=%d, mode=%d, size=%d", __func__, pgno, mode, size);
  SQLCIPHER_HEXDUMP("sqlcipher_page_cipher: input page data", in, page_sz);

  if(mode == SQLCIPHER_ENCRYPT) {
    /* start at front of the reserve block, write random data to the end */
    if((rc = ctx->provider->random(ctx->provider_ctx, reserve_out, ctx->reserve_sz)) != SQLITE_OK) goto error;
  } else { /* SQLCIPHER_DECRYPT */
    memcpy(reserve_out, reserve_in, ctx->reserve_sz); /* copy the entire reserve from the input to output buffer to ensure the iv and any random data at the end are available */
    sqlcipher_memset(tag_out, 0, ctx->tag_sz); /* wipe output tag, it will be recomputed */
  } 

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) && (mode == SQLCIPHER_DECRYPT)) {
    if((rc = sqlcipher_page_hmac(ctx, c_ctx, pgno, in, size + ctx->kbkdf_context_sz + ctx->iv_sz, tag_out)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: hmac operation on decrypt failed with error %d for pgno=%d", __func__, rc, pgno);
      goto error;
    }

    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: comparing tag on in=%p out=%p tag_sz=%d", __func__, tag_in, tag_out, ctx->tag_sz);
    if(sqlcipher_memcmp(tag_in, tag_out, ctx->tag_sz) != 0) { /* the hmac check failed */ 
      /* since the check failed, the page was either tampered with or corrupted. wipe the output buffer, 
         and return SQLITE_ERROR to the caller */
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: hmac check failed for pgno=%d", __func__, pgno);

      /* if the HMAC fails to verify on the first page, report SQLITE_NOTADB indicating that the file is either not encrypted
       * or the key is incorrect. If the failure occurs on a higher number page we assume that the first page has already
       * been successfully decrypted and verified, and thus, the failure on a higher number page represents a database
       * file corruption. This differentiation matches the behavior of SQLCipher pre-v5, where the error codes were
       * returned by SQLite instead of directly by SQLCipher through the VFS */
      rc = pgno == 1 ? SQLITE_NOTADB : SQLITE_CORRUPT;
      goto error;
    }
  } 
  
  sqlcipher_shield(c_ctx->key, ctx->key_sz);

  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_AEAD)) {
    /* Encrypt the page using AEAD. 
     *
     * NIST SP 800-38D states in section 8 that "The probability that the authenticated encryption function ever will be invoked with
     * the same IV and the same key on two (or more) distinct sets of input data shall be no greater than 2^-32.".
     *
     * Because of this a subkey is generated for each page write to prevent key & IV reuse with GCM, which could rapidly compromise
     * the security of the database. GCM's 96-bit IV alone only satisfies the NIST 2^-32 threshold up to 2^32 encryptions per key
     * so it would be possible for high-write-volume use cases to exhaust the IV safety factor if we used the master key directly.
     * This is especially true considering that a SQLite database may be written very frequently. 
     *
     * SQLCipher's default implementation is modeled after XAES-256-GCM (https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md)
     * where an SP 800-108 counter mode KDF is used in conjunction with AES-256-GCM. It's effective 192 bit nonce is split up in
     * so 96 bits is used as input context for the AES-256-CMAC KDF. The 96 bit IV is used as the GCM IV. This leaves the resulting 
     * page layout as follows,
     *
     *   |--------------------------------------------------------------------------------------------------------------------|
     *   | page data ...                  | page reserve (48 bytes)                                                           |
     *   |                                | KDF context (12 bytes) | IV (12 bytes) | tag (16 bytes) | unused random (8 bytes) |
     *   |--------------------------------------------------------------------------------------------------------------------|
     *
     * This combination allows use for up to 2^80 messages under the same input key (effectively pages, for SQLCipher) while
     * maintaining collision risk below 2^-32. 
     *
     * Note that in addition the default case already runs provided key material through PBKDF2 in order to generate the input key
     * when raw key syntax is not being used. 
     *
     * In practice this makes the total per-input-key cumulative write limit for any given master key 2^80 pages under the 800-38D
     * and 800-38B thresholds. This represents the write limit for the total number of page writes to the database file and any related
     * journals, including rewrites or existing pages (not the actual size of the file on disk). 2^80 pages is so large that effectively
     * a master key will never require rotation.
     *
     * This entire construct is based on standard constructs which meet FIPS 140 requirements.
     */
    rc = ctx->provider->aead_kbkdf(
      ctx->provider_ctx,
      c_ctx->key, ctx->key_sz,
      kbkdf_context_out, ctx->kbkdf_context_sz,
      c_ctx->subkey
    );

    /* page number, big endian, is used as AAD for GCM */
    sqlite3Put4byte(pgno_raw, pgno); 

    if(rc == SQLITE_OK) {
      rc = ctx->provider->aead_cipher(
        ctx->provider_ctx, mode, 
        c_ctx->subkey, ctx->key_sz, iv_out,
        pgno_raw, sizeof(pgno_raw),
        in, size, 
        (mode == SQLCIPHER_ENCRYPT) ? tag_out : tag_in,
        out 
      );
    }

    /* wipe subkey and context */
    xoshiro_randomness(c_ctx->subkey, ctx->key_sz);

  } else {
    rc = ctx->provider->cipher(ctx->provider_ctx, mode, c_ctx->key, ctx->key_sz, iv_out, in, size, out);
  }

  sqlcipher_shield(c_ctx->key, ctx->key_sz);

  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, 
      "%s: %s operation mode=%d failed with error %d for pgno=%d", 
      __func__, SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_AEAD) ? "cipher_aead" : "cipher",  mode, rc, pgno);

    /* if decryption fails the probably reason is an incorrect key or use of a non-encrypted database
     * so adjust the error code accordingly. Returns NOTADB for the first page, CORRUPT for higher
     * number pages consistent with explaination above in this function */
    if(mode == SQLCIPHER_DECRYPT) {
      rc = (pgno == 1 ? SQLITE_NOTADB : SQLITE_CORRUPT);
    }

    goto error;
  };
 
  if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) && (mode == SQLCIPHER_ENCRYPT)) {
    if((rc = sqlcipher_page_hmac(ctx, c_ctx, pgno, out_start, size + ctx->kbkdf_context_sz + ctx->iv_sz, tag_out)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: hmac operation on encrypt failed with error %d for pgno=%d", __func__, rc, pgno);
      goto error;
    }; 
  }

  SQLCIPHER_HEXDUMP("sqlcipher_page_cipher: output page data", out_start, page_sz);

  /* if this is a decrypt operation, we need to zero out the reserve so page checksums can be calculated based on the
   * data that SQLite originally wrote without the data we stuffed into the reserve */
  if(mode == SQLCIPHER_DECRYPT) sqlcipher_memset(reserve_out, 0, ctx->reserve_sz);

  rc = SQLITE_OK;
  goto cleanup;

error:
  sqlcipher_memset(out, 0, page_sz); 

cleanup:
  return rc;
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
static int sqlcipher_cipher_ctx_key_derive(sqlcipher_ctx *ctx, cipher_ctx *c_ctx) {
  int rc, raw_key_sz = 0, raw_salt_sz = 0, blob_format = 0, derive_hmac_key = 1, multiplier = 1, key_sz = 0;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: ctx->kdf_salt_sz=%d ctx->kdf_iter=%d ctx->key_sz=%d",
    __func__, ctx->kdf_salt_sz, ctx->kdf_iter, ctx->key_sz);

  /* if key material is present on the context for derivation */
  if(!c_ctx->pass || !c_ctx->pass_sz) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: key material is not present on the context for key derivation", __func__);
    return SQLITE_ERROR;
  }

  /* if necessary, initialize the salt from the header or random source */
  if(!SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT)) {
    if((rc = sqlcipher_ctx_init_kdf_salt(ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d from sqlcipher_ctx_init_kdf_salt", __func__, rc);
      goto error;
    }
  }

  /* raw key hex encoded is 2x long */
  raw_key_sz = ctx->key_sz * 2;
  raw_salt_sz = ctx->kdf_salt_sz *2;

  /* raw key must be a valid length and be properly BLOB formatted */
  blob_format = 0;
  if(c_ctx->pass_sz == raw_key_sz + 3
     || c_ctx->pass_sz == raw_key_sz + raw_salt_sz + 3
     || c_ctx->pass_sz == (raw_key_sz * 2) + raw_salt_sz + 3
  ) {
    int check = 1;
    check &= (c_ctx->pass[0] | 0x20) == 'x'; /* first char check (|%20 converts X to x)*/
    check &= c_ctx->pass[1] == '\''; /* second char is ' */
    check &= c_ctx->pass[c_ctx->pass_sz - 1] == '\''; /* last char is ' */
    check &= cipher_isHex(c_ctx->pass + 2, c_ctx->pass_sz - 3); /* wraps a valid hex string */
    blob_format = check;
  }
  
  /* derive_hmac_key will be set based on context flags and the type of key (i.e. raw key vs standard key materal) to determine whether
   * to perform an extra HMAC key derivation step via legacy fast kdf */

  if(blob_format && c_ctx->pass_sz == raw_key_sz + 3) {
    /* case 1 - raw key consisting of only the encryption key (i.e. no hmac key, and no salt) */
    const unsigned char *z = c_ctx->pass + 2; /* adjust lead offset of x' */
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw key only", __func__);
    cipher_hex2bin(z, raw_key_sz, c_ctx->key);
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: use of legacy raw key format with encryption key only, consider updating to use full keyspec format", __func__);
    derive_hmac_key = SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC); /* if we are using HMAC with a keyspec and there is no explicit hmac key, force legacy HMAC key derivation */
  } else if(blob_format && c_ctx->pass_sz == raw_key_sz + raw_salt_sz + 3) {
    /* case 2 - raw key consisting of the encryption key and salt (i.e. no hmac key) */
    const unsigned char *z = c_ctx->pass + 2;
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw key and salt", __func__);
    cipher_hex2bin(z, raw_key_sz, c_ctx->key);
    cipher_hex2bin(z + raw_key_sz, raw_salt_sz, ctx->kdf_salt);
    derive_hmac_key = SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC); /* if we are using HMAC with a keyspec and there is no explicit hmac key, force legacy HMAC key derivation */
  } else if(blob_format && c_ctx->pass_sz == (raw_key_sz * 2) + raw_salt_sz + 3) {
    /* option 3 - raw key, full keyspec consisting of the encryption key, an hmac key, and a salt */
    const unsigned char *z = c_ctx->pass + 2;
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw key, hmac key, and salt", __func__);
    cipher_hex2bin(z, raw_key_sz, c_ctx->key);
    cipher_hex2bin(z + raw_key_sz, raw_key_sz, c_ctx->hmac_key);
    cipher_hex2bin(z + raw_key_sz + raw_key_sz, raw_salt_sz, ctx->kdf_salt);
    derive_hmac_key = 0; /* if the keyspec contains an explicit hmac key then use it directly (never do legacy HMAC key derivation) */ 
  } else {
    /* in this block we are not using a raw key at all. We will only do the legacy HMAC key derivation if HMAC is enabled and
     * By default if HMAC is enabled and fast-kdf is off the HMAC key will be derived at the same time as the encryption key by
     * requesting extra bytes from PBKDF2. This is a beneficial optimization and avoids the second, low-iteration PBKDF2 operation.
     * If the fast-kdf flag is true (i.e. for version backwards compatibility with SQLCipher 1, 2, 3, or 4), legacy behavior using 
     * a second KDF step will be utilized for compatibility purposes */  
    derive_hmac_key = SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) && SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC_FAST_KDF);

    multiplier = !derive_hmac_key && SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) ? 2 : 1; /* if using HMAC, double the key size */
    key_sz = ctx->key_sz * multiplier;

    /* option 4, generate new key material using the provider KDF. Even if derive_hmac_key is true we will still generate
     * key_sz * 2 bytes here to establish the encryption key and the hmac key at the same time. Using the default algorthm
     * PBKDF2-HMAC-SHA512 generates the required number of bytes already, so there is no penalty to doing so. */
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: deriving key sz=%d using PBKDF2 with %d iterations", __func__, key_sz, ctx->kdf_iter);
    if((rc = ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->pass, c_ctx->pass_sz,
                  ctx->kdf_salt, ctx->kdf_salt_sz, ctx->kdf_iter,
                  key_sz, c_ctx->key)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred from provider kdf generating encryption key", __func__, rc);
      goto error;
    }
  }

  /* For legacy behavior of HMAC fast kdf generation, perform the second HMAC key generation step
   * using the output of the encryption key KDF as the input to this KDF run with a modified salt.
   * This will ensure a distinct but predictable HMAC key. */ 
  if(derive_hmac_key) {
    int i;
    /* Copy the kdf salt into the hmac salt slot then XOR it with the fixed hmac salt mask.
     * This ensures that the salt used to derive the hmac key is not the same as the salt used 
     * to generate the encryption key */
    memcpy(ctx->hmac_kdf_salt, ctx->kdf_salt, ctx->kdf_salt_sz);
    for(i = 0; i < ctx->kdf_salt_sz; i++) {
      ctx->hmac_kdf_salt[i] ^= HMAC_SALT_MASK;
    }

    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: deriving legacy hmac key from encryption key using PBKDF2 with %d iterations",
      __func__, FAST_PBKDF2_ITER);

    /* Perform the second round key derviation over the previously derived key using the new salt */
    if((rc = ctx->provider->kdf(ctx->provider_ctx, ctx->kdf_algorithm, c_ctx->key, ctx->key_sz,
                  ctx->hmac_kdf_salt, ctx->kdf_salt_sz, FAST_PBKDF2_ITER,
                  ctx->key_sz, c_ctx->hmac_key)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred from provider kdf generating HMAC key", __func__, rc);
      goto error;
    }
  }

  if(ctx->provider->aead_kbkdf) {
    if((rc = ctx->provider->aead_kbkdf(
      ctx->provider_ctx,
      c_ctx->key, ctx->key_sz,
      (unsigned char *)"sqlitecksums", 12,
      c_ctx->cksum_key
    )) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred deriving checksum key", __func__, rc);
      goto error;
    }
  } else {
    if((rc = ctx->provider->random(ctx->provider_ctx, c_ctx->cksum_key, ctx->key_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred generating random checksum key", __func__, rc);
      goto error;
    }
  }
  
  sqlcipher_shield(c_ctx->key, ctx->key_sz);
  sqlcipher_shield(c_ctx->hmac_key, ctx->key_sz);
  sqlcipher_shield(c_ctx->cksum_key, ctx->key_sz);
  c_ctx->derive_key = 0;
  return SQLITE_OK;

error:
  /* if an error occurred, overwrite any derived key material */

  xoshiro_randomness(c_ctx->key, ctx->key_sz);
  xoshiro_randomness(c_ctx->hmac_key, ctx->key_sz);
  xoshiro_randomness(c_ctx->cksum_key, ctx->key_sz);
  return rc;
}

static int sqlcipher_ctx_key_derive(sqlcipher_ctx *ctx) {
  int rc;

  /* derive key on first use if necessary */
  if(ctx->read_ctx->derive_key) {
    if((rc = sqlcipher_cipher_ctx_key_derive(ctx, ctx->read_ctx)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred deriving read_ctx key", __func__, rc);
      return rc;
    }
  }

  if(ctx->write_ctx->derive_key) {
    if(sqlcipher_cipher_ctx_pass_cmp(ctx->write_ctx, ctx->read_ctx) == 0) {
      /* the read and write key also needed to be derived, but the input key material matches on both contexts, 
       * so copy the read context over directly as an optimization to avoid repeated key derivation */
      if((rc = sqlcipher_cipher_ctx_copy(ctx, ctx->write_ctx, ctx->read_ctx)) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred copying read_ctx to write_ctx", __func__, rc);
        return rc;
      }
    } else {
      if((rc = sqlcipher_cipher_ctx_key_derive(ctx, ctx->write_ctx)) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred deriving write_ctx key", __func__, rc);
        return rc;
      }
    }
  }

  /* wipe and free passphrase after key derivation */
  sqlcipher_cipher_ctx_set_pass(ctx->read_ctx, NULL, 0);
  sqlcipher_cipher_ctx_set_pass(ctx->write_ctx, NULL, 0);

  return SQLITE_OK; 
}

static int sqlcipher_ctx_key_copy(sqlcipher_ctx *ctx, int source) {
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

static int sqlcipher_ctx_integrity_check(sqlcipher_ctx *ctx, Parse *pParse, char *column) {
  Pgno page = 1;
  char *result;
  sqlite3_file *fd = NULL;
  i64 file_sz;

  Vdbe *v = sqlite3GetVdbe(pParse);
  sqlite3VdbeSetNumCols(v, 1);
  sqlite3VdbeSetColName(v, 0, COLNAME_NAME, column, SQLITE_STATIC);

  if(ctx == NULL) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "not an encrypted database", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  fd = sqlite3PagerFile(sqlite3BtreePager(ctx->pBt));

  if(fd == NULL || fd->pMethods == 0) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "database file is undefined", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  if(!(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC) || SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_AEAD))) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "Authentication is not enabled, unable to integrity check", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  if(sqlcipher_ctx_key_derive(ctx) != SQLITE_OK) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "unable to derive keys", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  SQLCIPHER_FLAG_SET(((sqlcipher_file*) fd)->flags, SQLCIPHER_FILE_PASSTHROUGH_READ); /* disable VFS decryption temporarily */

  if(sqlite3OsFileSize(fd, &file_sz) != SQLITE_OK) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "failed to determine file size", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  if(ctx->plaintext_header_sz < 0) {
    sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "invalid plaintext header size", P4_TRANSIENT);
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    goto cleanup;
  }

  for(page = 1; page <= file_sz / ctx->page_sz; page++) {
    i64 offset = (page - 1) * (i64) ctx->page_sz;
    int read_sz = ctx->page_sz;

    /* skip integrity check on PAGER_SJ_PGNO since it will have no valid content */
    if(sqlite3pager_is_sj_pgno(sqlite3BtreePager(ctx->pBt), page)) continue;

    if(page==1) {
      int page1_offset = ctx->plaintext_header_sz ? ctx->plaintext_header_sz : FILE_HEADER_SZ;
      read_sz = read_sz - page1_offset;
      offset += page1_offset;
    }

    sqlcipher_memset(ctx->page_data, 0, ctx->page_sz);
    sqlcipher_memset(ctx->buffer, 0, ctx->page_sz);

    if(sqlite3OsRead(fd, ctx->page_data, read_sz, offset) != SQLITE_OK) {
      result = sqlite3_mprintf("error reading %d bytes from file page %d at offset %lld", read_sz, page, offset);
      if(result) {
        sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
      } else {
        sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "error reading from file (OOM)" , P4_STATIC);
      }
      sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    } else if(sqlcipher_page_cipher(ctx, CIPHER_READ_CTX, page, SQLCIPHER_DECRYPT, read_sz, ctx->page_data, ctx->buffer) != SQLITE_OK) {
      result = sqlite3_mprintf("Verification failed for page %d", page);
      if(result) {
        sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
      } else {
        sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "Verification failed for page (OOM)" , P4_STATIC);
      }
      sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
    } 
  }

  if(file_sz % ctx->page_sz != 0) {
    result = sqlite3_mprintf("page %d has an invalid size of %lld bytes (expected %d bytes)", page, file_sz - ((file_sz / ctx->page_sz) * ctx->page_sz), ctx->page_sz);
    if(result) {
      sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, result, P4_DYNAMIC);
    } else {
      sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, "page has an invalid size (OOM)" , P4_STATIC);
    }
    sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
  }

cleanup:
  if(fd) SQLCIPHER_FLAG_UNSET(((sqlcipher_file*) fd)->flags, SQLCIPHER_FILE_PASSTHROUGH_READ); /* reset passthrough to enable decryption */ 
  return SQLITE_OK;
}

static int sqlcipher_ctx_migrate(sqlcipher_ctx *ctx) {
  int i, pass_sz, keyspec_sz, nRes, user_version, rc, rc_cleanup, oflags, migrated_db_filename_sz, attached = 0;
  sqlite3 *db = ctx->pBt->db;
  const char *db_filename = sqlite3_db_filename(db, "main");
  char *set_user_version = NULL, *pass = NULL, *attach_command = NULL, *migrated_db_filename = NULL, 
    *keyspec = NULL, *temp = NULL, *journal_mode = NULL, *set_journal_mode = NULL, *pragma_compat = NULL;
  Btree *pDest = NULL, *pSrc = NULL;
  sqlite3_file *srcfile, *destfile;
#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  LPWSTR w_db_filename = NULL, w_migrated_db_filename = NULL;
  int w_db_filename_sz = 0, w_migrated_db_filename_sz = 0;
#endif
  pass_sz = keyspec_sz = rc = user_version = 0;

  if(!db_filename || sqlite3Strlen30(db_filename) < 1) 
    goto cleanup; /* exit immediately if this is an in memory database */ 
  
  /* pull the provided password / key material off the current context */
  pass_sz = ctx->read_ctx->pass_sz;

  if(pass_sz < 1 || !ctx->read_ctx->pass) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: underived key material is not available. PRAGMA cipher_migrate MUST be run as the first operation after keying", __func__);
    rc = SQLITE_MISUSE;
    goto handle_error;
  }

  if(!(pass = sqlcipher_malloc(pass_sz+1))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate key material storage", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }
  memset(pass, 0, pass_sz+1);
  memcpy(pass, ctx->read_ctx->pass, pass_sz);

  /* Version 4 - current, no upgrade required, so exit immediately */
  rc = sqlcipher_check_connection(db_filename, pass, pass_sz, "", &user_version, &journal_mode);
  if(rc == SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: no upgrade required - exiting", __func__);
    goto cleanup;
  }

  for(i = 4; i > 0; i--) { /* attempt to detect versions 4, 3, 2, 1 */
    if(!(pragma_compat = sqlite3_mprintf("PRAGMA cipher_compatibility = %d;", i))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format pragma_compat", __func__);
      rc = SQLITE_NOMEM;
      goto handle_error;
    }

    rc = sqlcipher_check_connection(db_filename, pass, pass_sz, pragma_compat, &user_version, &journal_mode);
    if(rc == SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: version %d format found", __func__, i);
      goto migrate;
    }
    sqlite3_free(pragma_compat);
    pragma_compat = NULL;
  }
  
  /* if we exit the loop normally we failed to determine the version, this is an error */
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: unable to determine format version for upgrade: this may indicate custom settings were used ", __func__);
  rc = SQLITE_NOTADB;
  goto handle_error;

migrate:

  if(!(temp = sqlite3_mprintf("%s-migrated", db_filename))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format temp filename", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }

  /* overallocate migrated_db_filename, because sqlite3OsOpen will read past the null terminator
   * to determine whether the filename was URI formatted */
  migrated_db_filename_sz = sqlite3Strlen30(temp)+2;
  if(!(migrated_db_filename = sqlcipher_malloc(migrated_db_filename_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate migrated db filename", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }

  memcpy(migrated_db_filename, temp, sqlite3Strlen30(temp));
  sqlite3_free(temp);
  temp = NULL;

  if(!(attach_command = sqlite3_mprintf("ATTACH DATABASE %Q as migrate;", migrated_db_filename))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate attach command", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }

  if(!(set_user_version = sqlite3_mprintf("PRAGMA migrate.user_version = %d;", user_version))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate user_version command", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }

  rc = sqlite3_exec(db, pragma_compat, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: set compatibility mode failed, error code %d", __func__, rc);
    goto handle_error;
  }

  /* force journal mode to DELETE, we will set it back later if different */
  rc = sqlite3_exec(db, "PRAGMA journal_mode = delete;", NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: force journal mode DELETE failed, error code %d", __func__, rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, attach_command, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: attach failed, error code %d", __func__, rc);
    goto handle_error;
  }
  attached = 1;

  rc = sqlite3_key_v2(db, "migrate", pass, pass_sz);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: keying attached database failed, error code %d", __func__, rc);
    goto handle_error;
  }

  rc = sqlite3_exec(db, "SELECT sqlcipher_export('migrate');", NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlcipher_export failed, error code %d", __func__, rc);
    goto handle_error;
  }

#ifdef SQLCIPHER_TEST
  if(SQLCIPHER_FLAG_GET(cipher_test_flags, TEST_FAIL_MIGRATE)) {
    rc = SQLITE_ERROR;
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: simulated migrate failure, error code %d", __func__, rc);
    goto handle_error;
  }
#endif

  rc = sqlite3_exec(db, set_user_version, NULL, NULL, NULL);
  if(rc != SQLITE_OK){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: set user version failed, error code %d", __func__, rc);
    goto handle_error;
  }

  if( !db->autoCommit ){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: cannot migrate from within a transaction", __func__);
    rc = SQLITE_MISUSE;
    goto handle_error;
  }
  if( db->nVdbeActive>1 ){
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: cannot migrate - SQL statements in progress", __func__);
    rc = SQLITE_MISUSE;
    goto handle_error;
  }

  /* all the content from the main database has now been exported to the migration database. The functionw will now
     perform a "switch" to overwrite the main database file with the migration database file while both databases are
     technically open */

  /* obtain a handle to the Btrees in use. in this context
     pDest - the main database, where we ultimately want the migrated data to wind up.
     pSrc - the attached database, where the migrated data was copied */
  pDest = db->aDb[0].pBt;
  pSrc = db->aDb[db->nDb-1].pBt;

  nRes = sqlite3BtreeGetRequestedReserve(pSrc);
  /* unset the BTS_PAGESIZE_FIXED flag to avoid SQLITE_READONLY */
  pDest->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED; 
  rc = sqlite3BtreeSetPageSize(pDest, default_page_size, nRes, 0);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to set btree page size to %d res %d rc %d", __func__, default_page_size, nRes, rc);
    goto handle_error;
  }

  /* extract the keyspec from the migrated database */
  if((rc = sqlcipher_db_get_key(db, db->nDb - 1, (void**)&keyspec, &keyspec_sz)) != SQLITE_OK || keyspec_sz < 1 || !keyspec) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to retrieve keyspec from migrated database", __func__);
    goto handle_error;
  }
  
  /* obtain pointers to the underlying sqlite3_files that are backing the Btree
     and close each of them. These will be reopened later once the files on disk
     are moved around 

     NOTE: the SQLCipher VFS will automatically wipe the sqlcipher_ctx instances attached
     to these files, so following this point the ctx pointer parameter is invalid
     and should not be used */
  destfile = sqlite3PagerFile(sqlite3BtreePager(pDest));
  sqlite3OsClose(destfile); 

  srcfile = sqlite3PagerFile(sqlite3BtreePager(pSrc));
  sqlite3OsClose(srcfile);

#ifdef SQLCIPHER_TEST
  if(SQLCIPHER_FLAG_GET(cipher_test_flags, TEST_FAIL_MIGRATE_CLOSED)) {
    rc = SQLITE_ERROR;
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: simulated migrate failure after close, error code %d", __func__, rc);
    goto handle_error;
  }
#endif

  /* now that both file handles are closed, use the OS file API to move / rename
     temporary migration file created by the export, overwriting the original file
     that was used by the main database. */
#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: performing windows MoveFileExA", __func__);

  w_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) db_filename, -1, NULL, 0);
  if(!(w_db_filename = sqlcipher_malloc(w_db_filename_sz * sizeof(wchar_t)))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate wide filename", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }
  w_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) db_filename, -1, (const LPWSTR) w_db_filename, w_db_filename_sz);

  w_migrated_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) migrated_db_filename, -1, NULL, 0);
  if(!(w_migrated_db_filename = sqlcipher_malloc(w_migrated_db_filename_sz * sizeof(wchar_t)))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate wide migrated filename", __func__);
    rc = SQLITE_NOMEM;
    goto handle_error;
  }
  w_migrated_db_filename_sz = MultiByteToWideChar(CP_UTF8, 0, (LPCCH) migrated_db_filename, -1, (const LPWSTR) w_migrated_db_filename, w_migrated_db_filename_sz);

  if(!MoveFileExW(w_migrated_db_filename, w_db_filename, MOVEFILE_REPLACE_EXISTING)) {
    rc = SQLITE_ERROR;
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error occurred while renaming migration files %d", __func__, rc);
    goto handle_error;
  }
#else
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: performing POSIX rename", __func__);
  if (rename(migrated_db_filename, db_filename) != 0) {
    rc = SQLITE_ERROR;
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error occurred while renaming migration files %s to %s: %d", __func__, migrated_db_filename, db_filename, rc);
    goto handle_error;
  }
#endif
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: renamed migration database %s to main database %s: %d", __func__, migrated_db_filename, db_filename, rc);

  /* re-open the file handle to the now non-existant migration database. this will be closed on detach */
  rc = sqlite3OsOpen(db->pVfs, migrated_db_filename, srcfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to reopen migration database %s: %d", __func__, migrated_db_filename, rc);
    goto handle_error;
  }

  /* re-open the file handle to the main database and attach a fresh codex_ctx with the current key  */
  rc = sqlite3OsOpen(db->pVfs, db_filename, destfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: failed to reopen main database %s: %d", __func__, db_filename, rc);
    goto handle_error;
  }

  rc = sqlcipher_ctx_init(&((sqlcipher_file*) destfile)->ctx, &db->aDb[0], keyspec, keyspec_sz);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: dest context initialization failed rc=%d", __func__, rc);
    goto handle_error;
  }


  /* reset the main database pager */
  sqlite3pager_reset(sqlite3BtreePager(pDest));
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: reset pager", __func__);

handle_error:

  /* failure during the file swap above can leave the main database file handle closed (see TEST_FAIL_MIGRATE_CLOSED)
   * so reopen it and re-initialize the sqlcipher_ctx so cleanup is not run against a closed file */
  destfile = sqlite3PagerFile(sqlite3BtreePager(db->aDb[0].pBt));
  if(destfile->pMethods == 0) { /* file is closed */
    if((rc_cleanup = sqlite3OsOpen(db->pVfs, db_filename, destfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_MAIN_DB, &oflags)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to re-open database file in error handler %s: %d", __func__, db_filename, rc_cleanup);
      if(rc == SQLITE_OK) rc = rc_cleanup;
      goto cleanup;
    }
    if((rc_cleanup = sqlcipher_ctx_init(&((sqlcipher_file*) destfile)->ctx, &db->aDb[0], keyspec, keyspec_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to reattach sqlcipher_ctx in error handler: %d", __func__, rc_cleanup);
      if(rc == SQLITE_OK) rc = rc_cleanup;
      goto cleanup;
    }
  }

  if(attached) {
    /* if we previosuly sucessfully attached the migration database, detatch it now */
    rc_cleanup = sqlite3_exec(db, "DETACH DATABASE migrate;", NULL, NULL, NULL);
    if(rc_cleanup != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: DETACH DATABASE migrate failed: %d", __func__, rc_cleanup);
      /* only overwrite the rc in the cleanup stage if it is currently not an error. This will prevent overwriting a previous error that occured earlier in migration */
      if(rc == SQLITE_OK) { 
        rc = rc_cleanup;
      }
    }
  }

  sqlite3ResetAllSchemasOfConnection(db);
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: reset all schemas", __func__);

  /* if we temporarily took the database out of WAL mode (or other), switch it back */
  if(journal_mode) {
    if((set_journal_mode = sqlite3_mprintf("PRAGMA journal_mode = %s;", journal_mode))) {
      rc_cleanup = sqlite3_exec(db, set_journal_mode, NULL, NULL, NULL);
      if(rc_cleanup != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to re-set journal mode via %s: %d", __func__, set_journal_mode, rc_cleanup);
        if(rc == SQLITE_OK) {
          rc = rc_cleanup;
        }
      }
    }
  }

  if(rc != SQLITE_OK) {
    sqlcipher_ctx *main_ctx = ((sqlcipher_file*) destfile)->ctx;
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: an error occurred attempting to migrate the database - last error %d", __func__, rc);
    if(main_ctx) main_ctx->error = rc; /* set flag for deferred error */
    sqlite3pager_reset(sqlite3BtreePager(db->aDb[0].pBt));
  }

cleanup:
  /* remove the migration file */
  if(migrated_db_filename) {
    int del_rc = sqlite3OsDelete(db->pVfs, migrated_db_filename, 0);
    if(del_rc != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: migration database %s not deleted: %d", __func__, migrated_db_filename, del_rc);
    }
  }
  if(pass) sqlcipher_free(pass, pass_sz);
  if(keyspec) sqlcipher_free(keyspec, keyspec_sz);
  if(attach_command) sqlite3_free(attach_command);
  if(migrated_db_filename) sqlcipher_free(migrated_db_filename, migrated_db_filename_sz);
  if(set_user_version) sqlite3_free(set_user_version);
  if(set_journal_mode) sqlite3_free(set_journal_mode);
  if(journal_mode) sqlite3_free(journal_mode);
  if(pragma_compat) sqlite3_free(pragma_compat);
#if defined(_WIN32) || defined(SQLITE_OS_WINRT)
  if(w_db_filename) sqlcipher_free(w_db_filename, w_db_filename_sz * sizeof(wchar_t));
  if(w_migrated_db_filename) sqlcipher_free(w_migrated_db_filename, w_migrated_db_filename_sz * sizeof(wchar_t));
#endif

  return rc;
}

static int sqlcipher_ctx_add_random(sqlcipher_ctx *ctx, const char *zRight, int random_sz){
  const char *suffix = NULL;
  int n = 0;
  if(random_sz < 4) return SQLITE_MISUSE;

  suffix = &zRight[random_sz-1];
  n = random_sz - 3; /* adjust for leading x' and tailing ' */
  if (n > 0 
      && sqlite3StrNICmp((const char *)zRight ,"x'", 2) == 0
      && sqlite3StrNICmp(suffix, "'", 1) == 0
      && n % 2 == 0
      && cipher_isHex((const unsigned char *)zRight+2, n) 
  ) {
    int rc = 0;
    int buffer_sz = n / 2;
    unsigned char *random;
    const unsigned char *z = (const unsigned char *)zRight + 2; /* adjust lead offset of x' */
    sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: using raw random blob from hex", __func__);
    if(!(random = sqlcipher_malloc(buffer_sz))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate buffer for random data", __func__);
      return SQLITE_NOMEM;
    }
    memset(random, 0, buffer_sz);
    cipher_hex2bin(z, n, random);
    rc = ctx->provider->add_random(ctx->provider_ctx, random, buffer_sz);
    sqlcipher_free(random, buffer_sz);
    return rc;
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: attemt to add random with invalid format", __func__);
  return SQLITE_ERROR;
}

#define MAX_LOG_LEN 4096

#if defined(_WIN32)
/* On windows convert to utf-16 when writing to stderr or stdout to avoid
 * a potential exception when writing mixed context to those streams
 * when using the shell. This implements two variations of the code
 * one that operats on a stack buffer, and the other that will use heap
 * memory. The former is used for logging output since failure and log
 * operations in the allocation code could inadvertantly cause
 * recursion. The latter is used for profile output (i.e. containing SQL
 * statments which we can't control the length of, and will thus will
 * allocate heap mem for output. The conversion logic is identical between them */

/* this function uses stack and trauncates to 4K */
static int sqlcipher_fprintf(FILE* stream, const char* format, ...) {
  int sz;
  va_list ap;

  if (stream == stderr || stream == stdout) {
    char buffer[MAX_LOG_LEN];
    wchar_t wbuffer[MAX_LOG_LEN];

    va_start(ap, format);
    sqlite3_vsnprintf(sizeof(buffer), buffer, format, ap);
    va_end(ap);

    sz = (int)strlen(buffer);

    sz = MultiByteToWideChar(CP_UTF8, 0, buffer, sz, wbuffer, (int) (sizeof(wbuffer) / sizeof(wbuffer[0])) - 1);
    wbuffer[sz] = (wchar_t) 0;
    fputws(wbuffer, stream);
  } else {
    va_start(ap, format);
    sz = vfprintf(stream, format, ap);
    va_end(ap);
  }
  return sz;
}

/* this function allocates memory for the output */
static int sqlcipher_mfprintf(FILE* stream, const char* format, ...) {
  int sz;
  va_list ap;

  if (stream == stderr || stream == stdout) {
    char* buffer = NULL;
    wchar_t* wbuffer = NULL;

    va_start(ap, format);
    buffer = sqlite3_vmprintf(format, ap);
    va_end(ap);

    if(!buffer) return -1;
    sz = (int)strlen(buffer);

    wbuffer = sqlite3_malloc((sz + 1) * sizeof(wchar_t));
    if (!wbuffer){
      sqlite3_free(buffer);
      return -1;
    }

    sz = MultiByteToWideChar(CP_UTF8, 0, buffer, sz, wbuffer, sz);
    wbuffer[sz] = (wchar_t) 0;
    fputws(wbuffer, stream);

    sqlite3_free(wbuffer);
    sqlite3_free(buffer);
  } else {
    va_start(ap, format);
    sz = vfprintf(stream, format, ap);
    va_end(ap);
  }
  return sz;
}
#else
/* on all non-Windows platforms, defer to standard fprintf for output */
#define sqlcipher_fprintf fprintf
#define sqlcipher_mfprintf fprintf
#endif /* defined(_WIN32) */

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
    sqlcipher_mfprintf(f, SQLCIPHER_PROFILE_FMT, elapsed, sqlite3_sql((sqlite3_stmt*)stmt));
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
    case SQLCIPHER_LOG_VFS:
      return "VFS";
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

void sqlcipher_log_write() {

}

/* constants from https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-crt/misc/gettimeofday.c */
#define FILETIME_1970 116444736000000000ull /* seconds between 1/1/1601 and 1/1/1970 */
#define HECTONANOSEC_PER_SEC 10000000ull
void sqlcipher_log(unsigned int level, unsigned int source, const char *message, ...) {
  va_list params;
  va_start(params, message);
  char formatted[MAX_LOG_LEN];
  size_t len = 0;

#ifdef SQLCIPHER_DEBUG
#if defined(SQLCIPHER_OMIT_LOG_DEVICE) || (!defined(__ANDROID__) && !defined(__APPLE__))
    sqlite3_vsnprintf(MAX_LOG_LEN, formatted, message, params);
    sqlcipher_fprintf(stderr, "%s", formatted);
    sqlcipher_fprintf(stderr, "\n");
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
      sqlcipher_fprintf((FILE*)sqlcipher_log_file, "%s.%03d: %s\n", buffer, ms, formatted);
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
  sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: set log to %s", __func__, destination);
  return SQLITE_OK;
#endif
}

static void sqlcipher_vdbe_return_string(Parse *pParse, const char *zLabel, const char *value, int value_type){
  Vdbe *v = sqlite3GetVdbe(pParse);
  if(!value) return;
  sqlite3VdbeSetNumCols(v, 1);
  sqlite3VdbeSetColName(v, 0, COLNAME_NAME, zLabel, SQLITE_STATIC);
  sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, value, value_type);
  sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
}

void *sqlcipher_pager_get_ctx(Pager *pPager){
  sqlite3_file *f = sqlite3PagerFile(pPager);
  sqlcipher_file *sf = (sqlcipher_file *)f;

  if(f != NULL && f->pMethods != NULL && sf->ctx != NULL) {
    return sf->ctx;
  }
  return NULL;
}

static int sqlcipher_set_btree_pagesize(sqlite3 *db, Db *pDb, sqlcipher_ctx *ctx) {
  int rc, new;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: sqlite3BtreeSetPageSize() size=%d reserve=%d", __func__, ctx->page_sz, ctx->reserve_sz);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering database mutex %p", __func__, db->mutex);
  sqlite3_mutex_enter(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered database mutex %p", __func__, db->mutex);
  db->nextPagesize = ctx->page_sz; 

  /* before forcing the page size we need to unset the BTS_PAGESIZE_FIXED flag, else  
     sqliteBtreeSetPageSize will block the change  */
  pDb->pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
  rc = sqlite3BtreeSetPageSize(pDb->pBt, ctx->page_sz, ctx->reserve_sz, 0);

  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlite3BtreeSetPageSize returned %d", __func__, rc);
  }

  if((new = sqlite3BtreeGetPageSize(pDb->pBt)) != ctx->page_sz) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlite3BtreeGetPageSize does not match target %d got %d", __func__, ctx->page_sz, new);
    rc = SQLITE_ERROR;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving database mutex %p", __func__, db->mutex);
  sqlite3_mutex_leave(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left database mutex %p", __func__, db->mutex);

  return rc;
}

#define SQLCIPHER_KEY_ERROR "An error occurred with PRAGMA key or rekey." \

static int sqlcipher_db_set_pass(sqlite3* db, int nDb, const void *zKey, int nKey, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p nDb=%d for_ctx=%d", __func__, db, nDb, for_ctx);
  if(pDb->pBt) {
    sqlcipher_ctx *ctx = (sqlcipher_ctx*) sqlcipher_pager_get_ctx(sqlite3BtreePager(pDb->pBt));

    if(ctx) {
      return sqlcipher_ctx_set_pass(ctx, zKey, nKey, for_ctx);
    } else {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error ocurred fetching context from pager on db %d", __func__, nDb);
      return SQLITE_ERROR;
    }
  }
  sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: no btree present on db %d", __func__, nDb);
  return SQLITE_ERROR;
} 

int sqlcipher_pragma(sqlite3* db, const char *zDb, int iDb, Parse *pParse, const char *zLeft, const char *zRight) {
  struct Db *pDb = &db->aDb[iDb];
  sqlcipher_ctx *ctx = NULL;
  int rc;

  if(pDb->pBt) {
    ctx = (sqlcipher_ctx*) sqlcipher_pager_get_ctx(sqlite3BtreePager(pDb->pBt));
  }

  if(
    sqlite3_stricmp(zLeft,"key")==0 || sqlite3_stricmp(zLeft,"rekey")==0 
    || sqlite3_stricmp(zLeft,"hexkey")==0 || sqlite3_stricmp(zLeft,"hexrekey")==0 
    || sqlite3_stricmp(zLeft,"textkey")==0 || sqlite3_stricmp(zLeft,"textrekey")==0 
  ) {
    if(zRight) {
      char zBuf[40];
      const char *zKey = zRight;
      int n = sqlite3Strlen30(zRight);

      if(sqlite3_stricmp(zLeft,"hexkey")==0 || sqlite3_stricmp(zLeft,"hexrekey") == 0){
        u8 iByte;
        int i;

        /* if hexkey or hexrekey are presented with any contents that contain invalid hex sequence,
         * error and return immediately */
        if(n % 2 != 0 || !cipher_isHex((const unsigned char *)zRight, n)) {
          sqlite3ErrorMsg(pParse, SQLCIPHER_KEY_ERROR);
          sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error provided with invalid hexkey", __func__);
          return 1;
        }

        for(i=0, iByte=0; i<sizeof(zBuf)*2 && sqlite3Isxdigit(zRight[i]); i++){
          iByte = (iByte<<4) + sqlite3HexToInt(zRight[i]);
          if( (i&1)!=0 ) zBuf[i/2] = iByte;
        }
        zKey = zBuf;
        n = i/2;
      }

      if(sqlite3_stricmp(zLeft,"key")==0 || sqlite3_stricmp(zLeft,"hexkey")==0 || sqlite3_stricmp(zLeft,"textkey")==0){
        rc = sqlite3_key_v2(db, zDb, zKey, n);
      }else{
        rc = sqlite3_rekey_v2(db, zDb, zKey, n);
      }

      if( rc==SQLITE_OK ){
        sqlcipher_vdbe_return_string(pParse, "ok", "ok", P4_TRANSIENT);
      } else {
        sqlite3ErrorMsg(pParse, SQLCIPHER_KEY_ERROR);
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error rc=%d from key operation", __func__, rc);
      }
    } else {
      sqlite3ErrorMsg(pParse, SQLCIPHER_KEY_ERROR);
    } 
    return 1; /* always stop processing for key pragmas prior */
  }

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p zDb=%s iDb=%d pParse=%p zLeft=%s zRight=%s ctx=%p", __func__, db, zDb, iDb, pParse, zLeft, zRight, ctx);

 #ifdef SQLCIPHER_TEST
  if( sqlite3_stricmp(zLeft,"cipher_selftest")==0 && !zRight){
    sqlcipher_selftest(db, pParse);
  } else
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
      } else
      if(sqlite3_stricmp(zRight, "fail_rekey")==0) {
        SQLCIPHER_FLAG_SET(cipher_test_flags,TEST_FAIL_REKEY);
      } else
      if(sqlite3_stricmp(zRight, "fail_migrate_closed")==0) {
        SQLCIPHER_FLAG_SET(cipher_test_flags,TEST_FAIL_MIGRATE_CLOSED);
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
      } else
      if(sqlite3_stricmp(zRight, "fail_rekey")==0) {
        SQLCIPHER_FLAG_UNSET(cipher_test_flags,TEST_FAIL_REKEY);
      } else
      if(sqlite3_stricmp(zRight, "fail_migrate_closed")==0) {
        SQLCIPHER_FLAG_UNSET(cipher_test_flags,TEST_FAIL_MIGRATE_CLOSED);
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
  if( sqlite3_stricmp(zLeft, "cipher_test_private_heap_used")== 0 && !zRight ){
    /* exposes a pragma to get the amount of memory currently allocated on the private heap
     * so that the test suite can check for memory leaks after failed operations */
#ifndef SQLCIPHER_OMIT_MALLOC
    char *used = sqlite3_mprintf("%u", private_heap_used);
    sqlcipher_vdbe_return_string(pParse, "cipher_test_private_heap_used", used, P4_DYNAMIC);
#else
    sqlcipher_vdbe_return_string(pParse, "cipher_test_private_heap_used", "0", P4_TRANSIENT);
#endif /* SQLCIPHER_OMIT_MALLOC */
  } else
#endif /* SQLCIPHER_TEST */
  if( sqlite3_stricmp(zLeft, "cipher_profile")== 0 && zRight ){
      char *profile_status = sqlite3_mprintf("%d", sqlcipher_cipher_profile(db, zRight));
      sqlcipher_vdbe_return_string(pParse, "cipher_profile", profile_status, P4_DYNAMIC);
  } else
  if( sqlite3_stricmp(zLeft, "cipher_add_random")==0 && zRight ){
    if(ctx) {
      char *add_random_status = sqlite3_mprintf("%d", sqlcipher_ctx_add_random(ctx, zRight, sqlite3Strlen30(zRight)));
      sqlcipher_vdbe_return_string(pParse, "cipher_add_random", add_random_status, P4_DYNAMIC);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_migrate")==0 && !zRight ){
    if(ctx){
      int status = sqlcipher_ctx_migrate(ctx); 
      char *migrate_status = sqlite3_mprintf("%d", status);
      sqlcipher_vdbe_return_string(pParse, "cipher_migrate", migrate_status, P4_DYNAMIC);
      if(status != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error occurred during cipher_migrate: %d", __func__, status);
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
  if( sqlite3_stricmp(zLeft,"cipher_default_kdf_iter")==0 ){
    if( zRight ) {
      int reqd = atoi(zRight);
      if(reqd >=1) default_kdf_iter = reqd; /* change default KDF iterations */ 
      else sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: ingoring request to set KDF to a negative number: %d", __func__, reqd); 
    } else {
      char *kdf_iter = sqlite3_mprintf("%d", default_kdf_iter);
      sqlcipher_vdbe_return_string(pParse, "cipher_default_kdf_iter", kdf_iter, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft, "kdf_iter")==0 ){
    if(ctx) {
      if( zRight ) {
        int reqd = atoi(zRight);
        if(reqd >=1) sqlcipher_ctx_set_kdf_iter(ctx, reqd); /* change of RW PBKDF2 iteration */ 
        else sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: ingoring request to set KDF to a negative number: %d", __func__, reqd); 
      } else {
        char *kdf_iter = sqlite3_mprintf("%d", ctx->kdf_iter);
        sqlcipher_vdbe_return_string(pParse, "kdf_iter", kdf_iter, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"page_size")==0 || sqlite3_stricmp(zLeft,"cipher_page_size")==0 ){
    /* PRAGMA cipher_page_size will alter the size of the database pages while ensuring that the
       required reserve space is allocated at the end of each page. This will also override the
       standard SQLite PRAGMA page_size behavior if a sqlcipher_ctx is attached to the database handle.
       If PRAGMA page_size is invoked but a sqlcipher_ctx is not attached (i.e. dealing with a standard
       unencrypted database) then return early and allow the standard PRAGMA page_size logic to apply. */
    if(ctx) {
      if( zRight ) {
        int size = atoi(zRight);
        rc = sqlcipher_ctx_set_pagesize(ctx, size);
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
        rc = sqlcipher_set_btree_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
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
  if( sqlite3_stricmp(zLeft,"cipher_default_aead")==0 ){
    if( zRight ) {
      sqlcipher_set_default_aead(sqlite3GetBoolean(zRight,1));
    } else {
      char *default_aead = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_AEAD));
      sqlcipher_vdbe_return_string(pParse, "cipher_default_aead", default_aead, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_aead")==0 ){
    if(ctx) {
      if( zRight ) {
        rc = sqlcipher_ctx_set_aead(ctx, sqlite3GetBoolean(zRight,1));
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
        /* since aead has changed, the page size may also change */
        rc = sqlcipher_set_btree_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
      } else {
        char *aead_flag = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_AEAD));
        sqlcipher_vdbe_return_string(pParse, "cipher_aead", aead_flag, P4_DYNAMIC);
      }
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
        rc = sqlcipher_ctx_set_use_hmac(ctx, sqlite3GetBoolean(zRight,1));
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
        /* since the use of hmac has changed, the page size may also change */
        rc = sqlcipher_set_btree_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
      } else {
        char *hmac_flag = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC));
        sqlcipher_vdbe_return_string(pParse, "cipher_use_hmac", hmac_flag, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_hmac_fast_kdf")==0 ){
    if( zRight ) {
      sqlcipher_set_default_hmac_fast_kdf(sqlite3GetBoolean(zRight,1));
    } else {
      char *val = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC_FAST_KDF));
      sqlcipher_vdbe_return_string(pParse, "cipher_default_hmac_fast_kdf", val, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_fast_kdf")==0 ){
    if(ctx) {
      if( zRight ) {
        rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, sqlite3GetBoolean(zRight,1));
        if(rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, rc);
      } else {
        char *flag = sqlite3_mprintf("%d", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC_FAST_KDF));
        sqlcipher_vdbe_return_string(pParse, "cipher_hmac_fast_kdf", flag, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_plaintext_header_size")==0 ){
    if(ctx) {
      if( zRight ) {
        int size = atoi(zRight);
        /* deliberately ignore result code, if size is invalid it will be set to -1
           and trip the error later in the process */
        sqlcipher_ctx_set_plaintext_header_size(ctx, size);
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
        if(
          sqlite3StrNICmp(zRight ,"x'", 2) == 0
          && sqlite3Strlen30(zRight) == (FILE_HEADER_SZ*2)+3
        ) {
          unsigned char *salt = NULL;
          const unsigned char *hex = (const unsigned char *)zRight+2;
           
          if(!cipher_isHex(hex, FILE_HEADER_SZ*2)) {
            sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
          } else if(!(salt = (unsigned char*) sqlite3_malloc(FILE_HEADER_SZ))) {
            sqlcipher_ctx_set_error(ctx, SQLITE_NOMEM);
          } else {
            cipher_hex2bin(hex,FILE_HEADER_SZ*2,salt);
            sqlcipher_ctx_set_kdf_salt(ctx, salt, FILE_HEADER_SZ);
            sqlite3_free(salt);
          }
        }
      } else {
        void *salt;
        char *hexsalt = NULL;
        if((hexsalt = (char*) sqlite3_malloc((FILE_HEADER_SZ*2)+1))) {
          if((rc = sqlcipher_ctx_get_kdf_salt(ctx, &salt)) == SQLITE_OK) {
            cipher_bin2hex(salt, FILE_HEADER_SZ, hexsalt);
            sqlcipher_vdbe_return_string(pParse, "cipher_salt", hexsalt, P4_DYNAMIC);
          } else {
            sqlite3_free(hexsalt);
            sqlcipher_ctx_set_error(ctx, rc);
          }
        } else {
          sqlcipher_ctx_set_error(ctx, SQLITE_NOMEM);
        }
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_algorithm")==0 ){
    if(ctx) {
      if(zRight) {
        rc = SQLITE_ERROR;
        if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA1_LABEL) == 0) {
          rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA256_LABEL) == 0) {
          rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA256);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA512_LABEL) == 0) {
          rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
        }
        if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
        rc = sqlcipher_set_btree_pagesize(db, pDb, ctx);
        if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
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
          rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL) == 0) {
          rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA256);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL) == 0) {
          rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
        }
        if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
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
            rc = sqlcipher_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_iter(ctx, 4000); 
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_aead(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_use_hmac(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 2: 
            rc = sqlcipher_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_iter(ctx, 4000); 
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_aead(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 3:
            rc = sqlcipher_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_iter(ctx, 64000); 
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_aead(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 4:
            rc = sqlcipher_ctx_set_pagesize(ctx, 4096);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_iter(ctx, 256000); 
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_aead(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          default:
            rc = sqlcipher_ctx_set_pagesize(ctx, 8192);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_kdf_iter(ctx, 512000); 
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_aead(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_use_hmac(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_ctx_set_hmac_fast_kdf(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
            break;
        }  

        rc = sqlcipher_set_btree_pagesize(db, pDb, ctx);
        if (rc != SQLITE_OK) sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
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
          sqlcipher_set_default_aead(0);
          sqlcipher_set_default_use_hmac(0);
          sqlcipher_set_default_hmac_fast_kdf(0);
          break;

        case 2: 
          default_page_size = 1024;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA1;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA1;
          default_kdf_iter = 4000;
          sqlcipher_set_default_aead(0);
          sqlcipher_set_default_use_hmac(1);
          sqlcipher_set_default_hmac_fast_kdf(1);
          break;

        case 3:
          default_page_size = 1024;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA1;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA1;
          default_kdf_iter = 64000;
          sqlcipher_set_default_aead(0);
          sqlcipher_set_default_use_hmac(1);
          sqlcipher_set_default_hmac_fast_kdf(1);
          break;

        case 4:
          default_page_size = 4096;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
          default_kdf_iter = 256000;
          sqlcipher_set_default_aead(0);
          sqlcipher_set_default_use_hmac(1);
          sqlcipher_set_default_hmac_fast_kdf(1);
          break;

        default:
          default_page_size = 8192;
          default_hmac_algorithm = SQLCIPHER_HMAC_SHA512;
          default_kdf_algorithm = SQLCIPHER_PBKDF2_HMAC_SHA512;
          default_kdf_iter = 512000;
          sqlcipher_set_default_aead(1);
          sqlcipher_set_default_use_hmac(0);
          sqlcipher_set_default_hmac_fast_kdf(0);
          break;
      }  
    } 
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_memory_security")==0 ){
    if( zRight ) {
      if(sqlite3GetBoolean(zRight,1)) {
        /* memory security can only be enabled, not disabled */
        sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: on", __func__);
        sqlcipher_mem_security_on = 1;
      }
    } else {
      /* only report that memory security is enabled if pragma cipher_memory_security is ON and
         SQLCipher's allocator/deallocator was run at least one time */
      int state = sqlcipher_mem_security_on && sqlcipher_mem_executed;
      char *on = sqlite3_mprintf("%d", state);
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE,
        "%s: sqlcipher_mem_security_on = %d, sqlcipher_mem_executed = %d", __func__, 
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

      pragma = sqlite3_mprintf("PRAGMA cipher_aead = %d;", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_AEAD));
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_use_hmac = %d;", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC));
      sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_hmac_fast_kdf = %d;", SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC_FAST_KDF));
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

    pragma = sqlite3_mprintf("PRAGMA cipher_default_aead = %d;", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_AEAD)); 
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_use_hmac = %d;", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC)); 
    sqlcipher_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_fast_kdf = %d;", SQLCIPHER_FLAG_GET(default_flags, CIPHER_FLAG_HMAC_FAST_KDF)); 
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
    sqlcipher_ctx_integrity_check(ctx, pParse, "cipher_integrity_check");
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
        else if(sqlite3_stricmp(zRight, "VFS"     )==0) SQLCIPHER_FLAG_SET(sqlcipher_log_source, SQLCIPHER_LOG_VFS);
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
#define SQLCIPHER_READ_OP 3
#define SQLCIPHER_WRITE_OP 6
#define SQLCIPHER_JOURNAL_OP 7

/*
 * sqlcipher_process_page can be called in multiple modes.
 * encrypt mode - expected to return a pointer to the 
 *   encrypted data without altering pData.
 * decrypt mode - expected to return a pointer to pData, with
 *   the data decrypted in the input buffer
 */
static void* sqlcipher_process_page(void *iCtx, void *data, Pgno pgno, int mode, int *rc_out) {
  sqlcipher_ctx *ctx = (sqlcipher_ctx *) iCtx;
  int offset = 0, rc = 0;
  unsigned char *pData = (unsigned char *) data;
  int cctx = CIPHER_READ_CTX;
  void *out = NULL;
  sqlite3_mutex *mutex = ctx->pBt->sharable ? sqlcipher_mutex(SQLCIPHER_MUTEX_SHAREDCACHE) : NULL;
  int plaintext_header_sz = ctx->plaintext_header_sz;

  /* in shared cache mode, this needs to be mutexed to prevent a separate database handle from
   * nuking the context on the shared Btree */
  if(mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering mutex %p", __func__, mutex);
    sqlite3_mutex_enter(mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered mutex %p", __func__, mutex);
  }

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: pgno=%d, mode=%d, ctx->page_sz=%d", __func__, pgno, mode, ctx->page_sz);

  if(ctx->error != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: identified deferred error condition: %d mode=%d", __func__, ctx->error, mode);
    sqlcipher_ctx_set_error(ctx, ctx->error);
    /* if this is a read, we don't want to return NULL as it will be interpreted as a SQLITE_NOMEM condition,
     * so instead return a zeroed out buffer that will fail the magic header check */
    if(mode == SQLCIPHER_READ_OP) { 
      sqlcipher_memset(pData, 0, ctx->page_sz);
      out = pData;
    } else {
      /* deferred errors must bubble-up from the VFS as I/O error to ensure that a rollback / pager cleanup can proceed cleanly */
      rc = SQLITE_IOERR; 
    }
    goto cleanup;
  }

  /* call to derive keys if not present yet */
  if((rc = sqlcipher_ctx_key_derive(ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error occurred during key derivation: %d", __func__, rc);
    sqlcipher_ctx_set_error(ctx, rc);
    goto cleanup;
  }

  /* if the plaintext_header_size is negative that means an invalid size was set via 
     PRAGMA. We can't set the error state on the pager at that point because the pager
     may not be open yet. However, this is a fatal error state, so abort */
  if(plaintext_header_sz < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error invalid plaintext_header_sz: %d", __func__, plaintext_header_sz);
    sqlcipher_ctx_set_error(ctx, SQLITE_ERROR);
    rc = SQLITE_ERROR;
    goto cleanup;
  }

  /* if this is a read operation on the first page, the plaintext header size has been set, but the data in
     the first 16 bytes of pData doesn't match the SQLite Header, then we are in a situatuon where 
     a migration is being attempted. The data on disk does not actually have a plaintext header, and it will not
     until the next write. Thefore we will temporarily defer the use of the plaintext header value */
  if(
    pgno == 1 && plaintext_header_sz && mode == SQLCIPHER_READ_OP 
    && memcmp(pData, (void*) SQLITE_FILE_HEADER, FILE_HEADER_SZ) != 0
  ) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, 
      "%s: inconsistent read operation, not using plaintext_header_sz=%d", __func__, plaintext_header_sz);
    plaintext_header_sz = 0;
  }

  if(pgno == 1) /* adjust starting pointers in data page for header offset on first page*/   
    offset = plaintext_header_sz ? plaintext_header_sz : FILE_HEADER_SZ; 
  

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: switch mode=%d offset=%d", __func__,  mode, offset);
  switch(mode) {
    case SQLCIPHER_READ_OP: /* decrypt */
      if(pgno == 1) /* copy initial part of file header or SQLite magic to buffer */ 
        memcpy(ctx->buffer, plaintext_header_sz ? pData : (void *) SQLITE_FILE_HEADER, offset); 

      rc = sqlcipher_page_cipher(ctx, cctx, pgno, SQLCIPHER_DECRYPT, ctx->page_sz - offset, pData + offset, (unsigned char*)ctx->buffer + offset);
#ifdef SQLCIPHER_TEST
      if(SQLCIPHER_FLAG_GET(cipher_test_flags, TEST_FAIL_DECRYPT) && sqlcipher_get_test_fail()) {
        rc = SQLITE_ERROR;
        sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: simulating decryption failure for pgno=%d, mode=%d, ctx->page_sz=%d", __func__, pgno, mode, ctx->page_sz);
      }
#endif
      if(rc != SQLITE_OK) {
        /* failure to decrypt a page is considered a permanent error and will render the pager unusable
         * in order to prevent inconsistent data being loaded into page cache. The only exception here is when a database is being "recovered",
         * which we consider to be the case if the plaintext header size is set to the full non-reserved size of a page. If that is the case we consider
         * this to be operating in recovery mode, and will log the error but not permanently put the context into an error state */
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error decrypting page %d data: %d", __func__, pgno, rc);
        sqlcipher_memset((unsigned char*) ctx->buffer+offset, 0, ctx->page_sz-offset);
        if(plaintext_header_sz == ctx->page_sz - ctx->reserve_sz) {
          sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: plaintext header size of %d indicates recovery mode, suppressing permanent error", __func__, plaintext_header_sz);
        } else {
          sqlcipher_ctx_set_error(ctx, rc);
        }
      } else {
        SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_KEY_USED);
      }
      memcpy(pData, ctx->buffer, ctx->page_sz); /* copy buffer data back to pData and return */
      out = pData;
      goto cleanup;
      break;

    case SQLCIPHER_WRITE_OP: /* encrypt database page, operate on write context and fall through to case 7, so the write context is used*/
      cctx = CIPHER_WRITE_CTX; 

    case SQLCIPHER_JOURNAL_OP: /* encrypt journal page, operate on read context use to get the original page data from the database */ 
      if(pgno == 1) { /* copy initial part of file header or salt to buffer */ 
        void *kdf_salt = NULL; 
        /* retrieve the kdf salt */
        if((rc = sqlcipher_ctx_get_kdf_salt(ctx, &kdf_salt)) != SQLITE_OK) {
          sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error retrieving salt: %d", __func__, rc);
          sqlcipher_ctx_set_error(ctx, rc); 
          goto cleanup;
        }
        memcpy(ctx->buffer, plaintext_header_sz ? pData : kdf_salt, offset);
      }
      rc = sqlcipher_page_cipher(ctx, cctx, pgno, SQLCIPHER_ENCRYPT, ctx->page_sz - offset, pData + offset, (unsigned char*)ctx->buffer + offset);
#ifdef SQLCIPHER_TEST
      if(SQLCIPHER_FLAG_GET(cipher_test_flags, TEST_FAIL_ENCRYPT) && sqlcipher_get_test_fail()) {
        rc = SQLITE_ERROR;
        sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: simulating encryption failure for pgno=%d, mode=%d, ctx->page_sz=%d", __func__, pgno, mode, ctx->page_sz);
      }
#endif
      if(rc != SQLITE_OK) {
        /* failure to encrypt a page is considered a permanent error and will render the pager unusable
           in order to prevent corrupted pages from being written to the main databased when using WAL */
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error encrypting page %d data: %d", __func__, pgno, rc);
        sqlcipher_memset((unsigned char*)ctx->buffer+offset, 0, ctx->page_sz-offset);
        sqlcipher_ctx_set_error(ctx, rc);
        goto cleanup;
      }
      SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_KEY_USED);
      out = ctx->buffer; /* return persistent buffer data, pData remains intact */
      goto cleanup;
      break;

    default:
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error unsupported mode %d", __func__, mode);
      sqlcipher_ctx_set_error(ctx, SQLITE_ERROR); /* unsupported mode, set error */
      out = pData;
      goto cleanup;
      break;
  }

cleanup:
  *rc_out = rc;

  if(mutex) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving mutex %p", __func__, mutex);
    sqlite3_mutex_leave(mutex);
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left mutex %p", __func__, mutex);
  }
  return out;
}

int sqlcipher_db_attach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  struct Db *pDb = NULL;
  sqlite3_file *fd = NULL;
  sqlcipher_ctx *ctx = NULL;
  Pager *pPager = NULL;
  int rc = SQLITE_OK;
  sqlite3_mutex *extra_mutex = NULL;
  sqlite3_vfs *vfs = NULL;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p, nDb=%d", __func__, db, nDb);

  if(!sqlcipher_init) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlcipher not initialized %d", __func__, sqlcipher_init_error);
    return sqlcipher_init_error;
  }

  /* error pKey is not null and nKey is > 0 */
  if(!(nKey > 0 && zKey)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: no key", __func__);
    return SQLITE_MISUSE;
  }

  if(!(db && nDb >= 0 && nDb < db->nDb && (pDb = &db->aDb[nDb]) && pDb->pBt)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: invalid database %p %d", __func__, db, nDb);
    return SQLITE_MISUSE;
  }

  /* Get the pointer to the current VFS being used for the target database connection and check that it is the sqlciphervfs. If not, 
   * this is an API misuse so return an error. This prevents attempts to try to set a key on a database with a non-sqlcipher VFS, which would
   * not actually encrypt the database in question. Example of this could happen if an application:
   *   1. an application registered a non-sqlcipher VFS as the default, bypassing the established default from sqlcipher_register_vfs()
   *   2. explicity unregistered the sqlciphervfs VFS
   *   3. opened a database using a URI that included a vfs= parameter other than sqlciphervfs
   * Each of these cases would bypass the sqlciphervfs and database encryption. Raising an error at the time the key is set will alert the
   * user / developer to the problem early to avoid unexpected behavior */
  if((rc = sqlite3_file_control(db, db->aDb[nDb].zDbSName, SQLITE_FCNTL_VFS_POINTER, &vfs)) != SQLITE_OK || vfs == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d retrieving current VFS for %p %d (%s)", __func__, rc, db, nDb, db->aDb[nDb].zDbSName);
    return SQLITE_ERROR;
  }
  if(sqlite3_stricmp(vfs->zName, "sqlciphervfs") != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: misuse attempting to set key on database with non-SQLCipher VFS", __func__);
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

  /* check if the sqlite3_file is present and the database is not a memory database. */
  fd = sqlite3PagerFile(pPager); 
  if(!fd || !fd->pMethods) {
    if(db->mDbFlags & DBFLAG_Vacuum) {
      /* if a VACUUM operation is running, it will attach a temp database, and attach.c will try to key it. skip keying this way.
       * The temp db in question will be in memory (not on disk) due to SQLITE_TEMP_STORE settings unless explicity overridden */
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: VACUUM is in process skipping context attach but permitting", __func__);
      goto cleanup;
    } else {
      /* attempt to key a memory or temp database outside of vacuum is a misuse error */
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: attach called on memory database", __func__);
      rc = SQLITE_MISUSE;
      goto error;
    }
  }

  ctx = (sqlcipher_ctx*) sqlcipher_pager_get_ctx(pPager);

  if(ctx != NULL) {
    /* There is already a sqlcipher_ctx attached to this database */
    if(SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_KEY_USED)) {
       /* The key was derived and used successfully, so return early */
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: disregarding attempt to set key on an previously keyed database connection handle", __func__);
      goto cleanup;
#ifndef SQLITE_DEBUG
    } else if (pDb->pBt->sharable) {
      /* This Btree is participating in shared cache. It would be usafe to reset and reattach a new sqlcipher_ctx, so return early.
       *
       * When compiled with SQLITE_DEBUG, all database connections have shared cached enabled. This behavior of disallowing reset
       * of the sqlcipher_ctx on a shared cache connection will break several tests that depend on the the ability to reset the context,
       * like migration tests, repeat-keying tests, etc. Asa result we will disable shared cache handling when compiled with
       * SQLIE_DEBUG enabled.*/
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: disregarding attempt to set key on an shared cache handle", __func__);
      goto cleanup;
#endif
    } else {
      /* To preseve legacy functionality where an incorrect key could be replaced by a correct key without closing the database,
       * if the key has not been used, and shared cache is not enabled, reset the sqlcipher_ctx on this pager entirely.
       * This will call sqlcipher_ctx_free directly because this function already
       * holds the shared cache mutex if it is necessary, and that avoids requiring a more expensive recursive mutex */
      sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: resetting existing sqlcipher_ctx on pager", __func__);
      sqlcipher_ctx_free(&ctx);
      ctx = NULL;
      ((sqlcipher_file *)fd)->ctx = NULL; /* context was freed on the fd, set NULL to avoid double free on cleanup if an error occurs */
    }
  }

  if((rc = sqlcipher_ctx_init(&ctx, pDb, zKey, nKey)) != SQLITE_OK) {
    /* initialization failed, do not attach potentially corrupted context */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: context initialization failed, forcing error state with rc=%d inTransaction=%d", __func__, rc, pDb->pBt->pBt->inTransaction);
    /* if an init failure occurs at this point try to make the database read only and mark the context for a permanent error state */
    sqlite3BtreeEnter(pDb->pBt);
    if(pDb->pBt->pBt->inTransaction != TRANS_WRITE) {
      pDb->pBt->pBt->btsFlags |= BTS_READ_ONLY;
    } 
    sqlite3BtreeLeave(pDb->pBt);
    ((sqlcipher_file *) fd)->init_error = rc; /* flag the sqlcipher_file as being in a permanent error state */
    pDb->pBt->pBt->db->errCode = rc;
    goto error;
  }

  if((rc = sqlcipher_set_btree_pagesize(db, pDb, ctx)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to set btree pagesize forcing fd error state with rc=%d", __func__, rc);
    ((sqlcipher_file *) fd)->init_error = rc; /* flag the sqlcipher_file as being in a permanent error state */
    pDb->pBt->pBt->db->errCode = rc;
    goto error;
  }

  /* force secure delete. This has the benefit of wiping internal data when deleted
     and also ensures that all pages are written to disk (i.e. not skipped by
     sqlite3PagerDontWrite optimizations) */
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlite3BtreeSecureDelete()", __func__);
  sqlite3BtreeSecureDelete(pDb->pBt, 1);

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: calling sqlite3BtreeSetAutoVacuum()", __func__);
  sqlite3BtreeSetAutoVacuum(pDb->pBt, SQLITE_DEFAULT_AUTOVACUUM);
 

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: attatching context to vfs", __func__);
  ((sqlcipher_file *)fd)->ctx = ctx; /* attach the newly created context to the sqlcipher file handle */

  goto cleanup;

error:
  if(ctx) sqlcipher_ctx_free(&ctx);

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

/* search for the index of the named database by comparing db names. main is
 * always 0, temp 1, and other attached databses follow. If the name is
 * NULL or empty the main database will be used consistent with sqlite defaults. If
 * sqlite3 handle is NULL or the database can't be found by name, return -1 indicating
 * an invalid database */
int sqlcipher_find_db_index(sqlite3 *db, const char *zDb) {
  int db_index;

  if(!db) return -1;
  if(!zDb || sqlite3_stricmp(zDb,"")==0) return 0;

  for(db_index = 0; db_index < db->nDb; db_index++) {
    struct Db *pDb = &db->aDb[db_index];
    if(sqlite3_stricmp(pDb->zDbSName, zDb) == 0) {
      return db_index;
    }
  }
  return -1;
}

/* Based directly on uriParameter from main.c */
static const char *sqlcipher_uri_parameter(const char *zFilename, const char *zParam){
  zFilename += sqlite3Strlen30(zFilename) + 1;
  while( ALWAYS(zFilename!=0) && zFilename[0] ){
    int x = strcmp(zFilename, zParam);
    zFilename += sqlite3Strlen30(zFilename) + 1;
    if( x==0 ) return zFilename;
    zFilename += sqlite3Strlen30(zFilename) + 1;
  }
  return 0;
}

/* Process URI filename query parameters relevant to SQLCipher
 * Return true if any of the relevant query parameters are
 * seen and return false if not.
*/
int sqlcipher_query_parameters (
  sqlite3 *db,           /* Database connection */
  const char *zDb,       /* Which schema is being created/attached */
  const char *zUri,       /* URI filename */
  int *seen
){
  const char *zKey;

  if( zUri==0 ){
    if(seen) *seen = 0;
  }else if( (zKey = sqlcipher_uri_parameter(zUri, "hexkey"))!=0 && zKey[0] ){
    u8 iByte;
    int i;
    char zDecoded[40];
    int n = sqlite3Strlen30(zKey);
    if(seen) *seen = 1;

    /* check that hexkey is valid */
    if(n % 2 != 0 || !cipher_isHex((const unsigned char *)zKey, n)) {
      return SQLITE_MISUSE;
    }

    for(i=0, iByte=0; i<sizeof(zDecoded)*2 && sqlite3Isxdigit(zKey[i]); i++){
      iByte = (iByte<<4) + sqlite3HexToInt(zKey[i]);
      if( (i&1)!=0 ) zDecoded[i/2] = iByte;
    }
    return sqlite3_key_v2(db, zDb, zDecoded, i/2);
  }else if( (zKey = sqlcipher_uri_parameter(zUri, "key"))!=0 ){
    if(seen) *seen = 1;
    return sqlite3_key_v2(db, zDb, zKey, sqlite3Strlen30(zKey));
  }else if( (zKey = sqlcipher_uri_parameter(zUri, "textkey"))!=0 ){
    if(seen) *seen = 1;
    return sqlite3_key_v2(db, zDb, zKey, -1);
  }else{
    if(seen) *seen = 0;
  }
  return SQLITE_OK;
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p", __func__, db);
  return sqlite3_key_v2(db, "main", pKey, nKey);
}

int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
  int db_index = sqlcipher_find_db_index(db, zDb);
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p zDb=%s db_index=%d", __func__, db, zDb, db_index);
  if(pKey && nKey < 0) {
    nKey = strlen(pKey);
  }
  return sqlcipher_db_attach(db, db_index, pKey, nKey);
}

int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p", __func__, db);
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

#define REKEY_NONE 0
#define REKEY_E2E  1
#define REKEY_P2E  2
#define REKEY_E2P  3

int sqlite3_rekey_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
  int db_index = -1;
  struct Db *pDb = NULL;
  sqlcipher_ctx *ctx = NULL;
  int rc = SQLITE_ERROR, page_count, rc_cleanup;
  Pgno pgno;
  PgHdr *page;
  Pager *pPager = NULL;
  sqlcipher_file *fd = NULL;
  char *vacuum_sql = NULL;
  char *page_size_sql = NULL;
  char *set_journal_delete_sql = NULL;
  char *set_journal_back_sql = NULL;
  char *get_journal_sql = NULL;
  char *journal_mode = NULL;
  sqlite3_stmt *stmt = NULL;
  int rekey_mode = REKEY_NONE;
  i64 file_sz = 0;
  int reserve_sz;
  const char *db_name = zDb ? zDb : "main";

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: db=%p zDb=%s", __func__, db, zDb);
  
  if(!sqlcipher_init) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlcipher not initialized %d",__func__, sqlcipher_init_error);
    return sqlcipher_init_error;
  }

  if(pKey && nKey < 0) {
    nKey = strlen(pKey);
  }

  if(!db) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: invalid database handle", __func__);
    return SQLITE_MISUSE;
  }

  db_index = sqlcipher_find_db_index(db, zDb);
  if(!(db_index >= 0 && db_index < db->nDb)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: invalid database zDb=%p", __func__, zDb);
    return SQLITE_MISUSE;
  }

  pDb = &db->aDb[db_index];
  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: database zDb=%p db_index:%d", __func__, zDb, db_index);

  if(!pDb->pBt) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: invalid database btree pDb=%p", __func__, pDb);
    return SQLITE_MISUSE;
  }

  /* get the pager and current sqlcipher_ctx if set */
  pPager = sqlite3BtreePager(pDb->pBt);
  fd = (sqlcipher_file *) sqlite3PagerFile(pPager);
  ctx = (sqlcipher_ctx*) sqlcipher_pager_get_ctx(pPager);

  if(!fd || !((sqlite3_file*)fd)->pMethods) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: rekey called on closed or in-memory database", __func__);
    return SQLITE_MISUSE;
  }

  if(sqlite3OsFileSize((sqlite3_file *)fd, &file_sz) != SQLITE_OK || file_sz == 0) {
    /* database has not been created yet, so no pages exist on disk. abort */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: empty database", __func__);
    return SQLITE_MISUSE;
  }

  if(!ctx && (!pKey || !nKey)) {
    /* current database is not encrypted and there is no key provided for the target. This is a no-op */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: rekey run on plaintext database with no key provided", __func__, pDb);
    return SQLITE_MISUSE;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering database mutex %p", __func__, db->mutex);
  sqlite3_mutex_enter(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered database mutex %p", __func__, db->mutex);

  /* grab existing journal mode, then set journal mode to delete. resizing and encrypted coversion will not work with WAL */
  if(!(get_journal_sql = sqlite3_mprintf("PRAGMA %w.journal_mode;", db_name))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format journal_mode query SQL", __func__);
    rc = SQLITE_NOMEM;
    goto cleanup;
  }

  if((rc = sqlite3_prepare(db, get_journal_sql, -1, &stmt, NULL)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: %s failed to prepare journal mode query for database %d", __func__, set_journal_delete_sql, rc);
    goto cleanup;
  }
 
  rc = sqlite3_step(stmt);
  if(rc == SQLITE_ROW) {
    if(!(journal_mode = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 0)))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format journal_mode SQL", __func__);
      rc = SQLITE_NOMEM;
      goto cleanup;
    }
  } else {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed step for journal query %d", __func__, rc);
    goto cleanup; 
  }
  sqlite3_finalize(stmt);
  stmt = NULL;
  
  if(!(set_journal_delete_sql = sqlite3_mprintf("PRAGMA %w.journal_mode = delete;", db_name))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format journal_mode=delete SQL", __func__);
    rc = SQLITE_NOMEM;
    goto cleanup;
  }

  if((rc = sqlite3_exec(db, set_journal_delete_sql, 0, 0, 0)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: %s failed to set journal mode for database %d", __func__, set_journal_delete_sql, rc);
    goto cleanup;
  } 

  if(!ctx) { 
    sqlcipher_ctx *temp_ctx = NULL;
    /* plaintext database conversion to encrypted */
    rekey_mode = REKEY_P2E;

    /* initialize a temporary sqlcipher_ctx object with all default settings. The context is detatched,
     * but will allow us to query what reserve size should be based on all the relevant default settings
     * which is a complex process. after getting the reserve size free it immediately */ 
    if((rc = sqlcipher_ctx_init(&temp_ctx, pDb, "x", 1)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to initilize temporary sqlcipher_ctx %d", __func__, rc);
      goto cleanup; 
    }
    reserve_sz = temp_ctx->reserve_sz;
    sqlcipher_ctx_free(&temp_ctx);

    /* prepare the SQL that will need to be executed to adjust page size and vacuum the database */
    if(!(page_size_sql = sqlite3_mprintf("PRAGMA %w.page_size = %d", db_name, default_page_size))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format PRAGMA page_size SQL", __func__);
      rc = SQLITE_NOMEM;
      goto cleanup;
    }

    if(!(vacuum_sql = sqlite3_mprintf("VACUUM %w", db_name))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format VACUUM SQL", __func__);
      rc = SQLITE_NOMEM;
      goto cleanup;
    }

    /* aligning the database page size and reserve size must happen for an unencrypted database
     * before we can encrypt it. This is a two step process, first the page size must be increased
     * or decreased to the sqlcipher default and vacuumed if necessary. We only run step one if the 
     * page size is different from the default. Then the reserve bytes must be set with sqlite3_file_control,
     * and the database re-vacuumed.*/
    if(sqlite3BtreeGetPageSize(pDb->pBt) != default_page_size) {
      sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s: adjusting page size for database to %d with VACUUM", __func__, default_page_size);

      if((rc = sqlite3_exec(db, page_size_sql, 0, 0, 0)) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: %s failed to set page size for database %d", __func__, page_size_sql, rc);
        goto cleanup;
      } 

      if((rc = sqlite3_exec(db, vacuum_sql, 0, 0, 0)) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: %s failed for unencrypted db %d", __func__, vacuum_sql, rc);
        goto cleanup;
      } 
    }

    /* always set reserve bytes */
    if((rc = sqlite3_file_control(db, db_name, SQLITE_FCNTL_RESERVE_BYTES, &reserve_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: sqlite3_file_control error rc=%d n=%d", __func__, rc, reserve_sz);
      goto cleanup;
    }

    if((rc = sqlite3_exec(db, vacuum_sql, 0, 0, 0)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: %s failed for unencrypted db %d", __func__, vacuum_sql, rc);
      goto cleanup;
    } 

    /* attach new codec */  
    if((rc = sqlcipher_db_attach(db, db_index, pKey, nKey)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed attach sqlcipher to current db %d", __func__, rc);
      goto cleanup;
    }

    if(!(ctx = (sqlcipher_ctx *) sqlcipher_pager_get_ctx(pPager))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to retrieve encryption context from current db", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }

    SQLCIPHER_FLAG_SET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_READ);

    /* generate new random sale. we do this now because otherwise the default path for key derviation would
     * read the first 16 bytes of the database file and use it as salt, which would always be "SQlite Format 3"
     * since the origin database is not encrypted */
    if((rc = ctx->provider->random(ctx->provider_ctx, (void *)ctx->kdf_salt, ctx->kdf_salt_sz)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_MEMORY, "%s: failed to generate rekey database salt %d", __func__, rc); 
      goto cleanup; 
    }
    SQLCIPHER_FLAG_SET(ctx->flags, CIPHER_FLAG_HAS_KDF_SALT);

  } else if(!(pKey && nKey)) {
    /* encrypted database conversion to plaintext */
    rekey_mode = REKEY_E2P;
    SQLCIPHER_FLAG_SET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_WRITE);
  } else {
    /* encrypted database to encryped database with different key */
    rekey_mode = REKEY_E2E;
    if((rc = sqlcipher_db_set_pass(db, db_index, pKey, nKey, CIPHER_WRITE_CTX)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to set key on write cipher_ctx %d", __func__, rc);
      goto cleanup;
    }
  } 

  sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: starting rekey on %s", __func__, zDb);

  /* Rewrite the database 
  ** 1. Create a transaction on the database
  ** 2. Iterate through each page, reading it and then writing it.
  ** 3. If that goes ok then commit and ensure write key is synced up with read key
  **    note: don't deallocate rekey since it may be used in a subsequent iteration 
  */
  if((rc = sqlite3BtreeBeginTrans(pDb->pBt, 1, 0)) != SQLITE_OK) { /* begin write transaction */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to begin write transaction %d", __func__, rc);
    goto cleanup;
  } 
  sqlite3PagerPagecount(pPager, &page_count);
  for(pgno = 1; rc == SQLITE_OK && pgno <= (unsigned int)page_count; pgno++) { /* pgno's start at 1 see pager.c:pagerAcquire */
    if(!sqlite3pager_is_sj_pgno(pPager, pgno)) { /* skip this page (see pager.c:pagerAcquire for reasoning) */
      rc = sqlite3PagerGet(pPager, pgno, &page, 0);
      if(rc == SQLITE_OK) { /* write page see pager_incr_changecounter for example */
        if((rc = sqlite3PagerWrite(page)) != SQLITE_OK) {
          sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred writing page %d", __func__, rc, pgno);  
        }
        sqlite3PagerUnref(page);
      } else {
         sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: error %d occurred reading page %d", __func__, rc, pgno);  
      }
    } 
#ifdef SQLCIPHER_TEST
    /* if testing rekey failure, error out half way through the rekey */
    if(SQLCIPHER_FLAG_GET(cipher_test_flags, TEST_FAIL_REKEY) && pgno > (unsigned int)(page_count / 2)) {
      sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_CORE, "%s: simulated rekey failure, error code %d", __func__, SQLITE_ERROR);
      rc = SQLITE_ERROR;
    }
#endif
  }

cleanup:
  if(vacuum_sql) sqlite3_free(vacuum_sql);
  if(page_size_sql) sqlite3_free(page_size_sql);
  if(set_journal_delete_sql) sqlite3_free(set_journal_delete_sql);
  if(get_journal_sql) sqlite3_free(get_journal_sql);
  if(stmt) sqlite3_finalize(stmt); 

  if(rc == SQLITE_OK && (rc = sqlite3BtreeCommit(pDb->pBt)) == SQLITE_OK) {
    /* the rekey was successful and commit succeeded*/
    switch(rekey_mode) {
      case REKEY_P2E:
        /* database is now encrypted, turn off read passthrough */
        SQLCIPHER_FLAG_UNSET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_READ);
        break; 
      case REKEY_E2P:
        /* the origin pager still is still setup for encyption, free and uninstall sqlcipher so it can be used normally */
        sqlcipher_ctx_free(&fd->ctx);
        break;
      case REKEY_E2E:
        /* copy write key back to read key */
        rc = sqlcipher_ctx_key_copy(ctx, CIPHER_WRITE_CTX);
        break; 
      case REKEY_NONE:
        /* do nothing */
        break; 
    }
  }

  if(rc != SQLITE_OK) {
    /* an error occurred during processing or the commit failed. attempt rollback */
    switch(rekey_mode) {
      case REKEY_P2E:
        /* contents of journal are encrypted because context was attached to teh database. If rekey failed
         * set passthrough write so that data is decrypted from journal but written to database file plaintext */
        SQLCIPHER_FLAG_SET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_WRITE);
        break; 
      case REKEY_E2P:
        /* contents of journal are encrypted, so turn off write passthrough before rollback*/
        SQLCIPHER_FLAG_UNSET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_WRITE);
        break;
      case REKEY_E2E:
        /* copy the read key back to write key before rolling back the transaction */ 
        rc_cleanup  = sqlcipher_ctx_key_copy(ctx, CIPHER_READ_CTX); 
        if(rc == SQLITE_OK) rc = rc_cleanup;
        break; 
      case REKEY_NONE:
        /* do nothing */
        break; 
    }

    if(sqlite3BtreeRollback(pDb->pBt, SQLITE_ABORT_ROLLBACK, 0) != SQLITE_OK) { 
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to rollback transaction on rekey %d", __func__, rc);
    }

    /* after rollbak on the the plaintext-to-encrypted, free the context to switch back to unencrypted database */
    if(rekey_mode == REKEY_P2E && fd->ctx) sqlcipher_ctx_free(&fd->ctx);
  }

  /* if we changed journal mode then switch it back */
  if(journal_mode) {
    if(!(set_journal_back_sql = sqlite3_mprintf("PRAGMA %w.journal_mode = %s;", db_name, journal_mode))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to format journal mode reset", __func__);
      if(rc == SQLITE_OK) rc = SQLITE_NOMEM; 
    } else {
      if((rc_cleanup = sqlite3_exec(db, set_journal_back_sql, NULL, NULL, NULL)) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to re-set journal mode via %s: %d", __func__, set_journal_back_sql, rc_cleanup);
        if(rc == SQLITE_OK) rc = rc_cleanup;
      }
    }
  }
  if(set_journal_back_sql) sqlite3_free(set_journal_back_sql);
  if(journal_mode) sqlite3_free(journal_mode);

  /* regardless of state, turn off passthroughs before returning */
  SQLCIPHER_FLAG_UNSET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_WRITE);
  SQLCIPHER_FLAG_UNSET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_READ);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving database mutex %p", __func__, db->mutex);
  sqlite3_mutex_leave(db->mutex);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left database mutex %p", __func__, db->mutex);

  sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_CORE, "%s: rekey complete with rc %d", __func__, rc);
  return rc;
}

/*
 * Retrieves the current key attached to the database if there is a context attached to it.
 * The key will be passed back using internally allocated memory and must be freed using
 * sqlcipher_free to avoid memory leaks. If no key is present, zKey will be set to NULL
 * and nKey to 0, which is the normal state for a plaintext database.
 *
 * If the encryption key has not yet been derived or the key material is stored, it will
 * be passed back directly. Otherwise, a "keyspec" consisting of the raw key and salt
 * will be used instead.
 *
 * If an error occurs retrieving the key for a database the error code will be returned */
int sqlcipher_db_get_key(sqlite3* db, int nDb, void **zKey, int *nKey) {
  struct Db *pDb = NULL;
  sqlcipher_ctx *ctx = NULL;

  sqlcipher_log(SQLCIPHER_LOG_DEBUG, SQLCIPHER_LOG_CORE, "%s:db=%p, nDb=%d", __func__, db, nDb);

  *zKey = NULL;
  *nKey = 0;

  if(!(db && nDb >= 0 && nDb < db->nDb) || !db->aDb[nDb].pBt) { 
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: called on invalid database", __func__);
    return SQLITE_MISUSE;
  }
  pDb = &db->aDb[nDb];

  if((ctx = (sqlcipher_ctx*) sqlcipher_pager_get_ctx(sqlite3BtreePager(pDb->pBt)))) {
    /* if the key has not been derived yet
     * then return the key material. Other wise pass back the keyspec */
    if(ctx->read_ctx->derive_key) {
      if(!(*zKey = sqlcipher_malloc(ctx->read_ctx->pass_sz))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_CORE, "%s: failed to allocate key storage", __func__);
        return SQLITE_NOMEM;
      }
      *nKey = ctx->read_ctx->pass_sz;
      memcpy(*zKey, ctx->read_ctx->pass, ctx->read_ctx->pass_sz);
    } else {
      return sqlcipher_cipher_ctx_get_keyspec(ctx, ctx->read_ctx, (char**) zKey, nKey);
    }
  }
  return SQLITE_OK;
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
    if(*pzErrMsg) sqlite3_free(*pzErrMsg);
    *pzErrMsg = sqlite3_mprintf("%s", sqlite3_errmsg(db));
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
    *pzErrMsg = sqlite3_mprintf("%s", sqlite3_errmsg(db));
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
  int targetDb_idx = 0, sourceDb_idx = 0;
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
      pzErrMsg = sqlite3_mprintf("source database can't be NULL");
      goto end_of_export;
    }
    sourceDb = (char *) sqlite3_value_text(argv[1]);
  }

  /* if the source database is not valid, do not proceed. */
  sourceDb_idx =  sqlcipher_find_db_index(db, sourceDb);
  if(sourceDb_idx < 0) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("invalid source database %s", sourceDb);
    goto end_of_export;
  }

  /* if the target database is not valid, do not proceed. */
  targetDb_idx =  sqlcipher_find_db_index(db, targetDb);
  if(targetDb_idx < 0) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("invalid target database %s", targetDb);
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
    "  FROM \"%w\".sqlite_schema WHERE type='table' AND name!='sqlite_sequence'"
    "   AND rootpage>0"
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM \"%w\".sqlite_schema WHERE sql LIKE 'CREATE INDEX %%' "
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM \"%w\".sqlite_schema WHERE sql LIKE 'CREATE UNIQUE INDEX %%'"
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Loop through the tables in the main database. For each, do
  ** an "INSERT INTO rekey_db.xxx SELECT * FROM main.xxx;" to copy
  ** the contents to the temporary database.
  */
  /* This block and the following one are modified from the standard escaping using
   * \"%w\" to instead use quote() around the internal SQL statement that is generated
   * for execution by execExecSql. this unfortunately relies on the non-standard
   * behavior (albeit which is also used for the table name) where "SQLite will sometimes bend the
   * quoting rules" such that "If a keyword in single quotes (ex: 'key' or 'glob') is used in a
   * context where an identifier is allowed but where a string literal is not allowed, then
   * the token is understood to be an identifier instead of a string literal."
   * per https://www.sqlite.org/lang_keywords.html */
  zSql = sqlite3_mprintf(
    "SELECT 'INSERT INTO ' || quote(%Q) || '.' || quote(name) "
    "|| ' SELECT * FROM ' || quote(%Q) || '.' || quote(name) || ';'"
    "FROM \"%w\".sqlite_schema "
    "WHERE type = 'table' AND name!='sqlite_sequence' "
    "  AND rootpage>0"
  , targetDb, sourceDb, sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Copy over the contents of the sequence table
  */
  zSql = sqlite3_mprintf(
    "SELECT 'INSERT INTO ' || quote(%Q) || '.' || quote(name) "
    "|| ' SELECT * FROM ' || quote(%Q) || '.' || quote(name) || ';' "
    "FROM \"%w\".sqlite_schema WHERE name=='sqlite_sequence';"
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
    "INSERT INTO \"%w\".sqlite_schema "
    "  SELECT type, name, tbl_name, rootpage, sql"
    "    FROM \"%w\".sqlite_schema"
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
      sqlite3_free(pzErrMsg);
    } else {
      sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
    }
  }
}

/* Implementation of SQLCipher VFS */

static sqlcipher_file *sqlcipher_files_open = NULL; 
 
int sqlcipher_register_vfs(void){
  sqlite3_vfs *pOrig = NULL;
  int rc = SQLITE_ERROR;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: called", __func__);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_VFS", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_VFS", __func__);

  pOrig = sqlite3_vfs_find(0);

  if( pOrig==0 ) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: unable to locate default vfs", __func__);
    rc = SQLITE_ERROR;
    goto end;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: current default vfs is %s", __func__, pOrig->zName);

  if(sqlite3_stricmp(pOrig->zName, "sqlciphervfs") == 0) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: sqlciphervfs is already default, returning", __func__);
    rc = SQLITE_OK;
    goto end;
  } else if( sqlite3_vfs_find("sqlciphervfs")!=0 ) {
    sqlcipher_log(SQLCIPHER_LOG_WARN, SQLCIPHER_LOG_VFS, "%s: located previously registered sqlciphervfs that is NOT default, unregistering", __func__);
    sqlite3_vfs_unregister(&sqlcipher_vfs);
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: registering sqlciphervfs", __func__);
  sqlcipher_vfs.iVersion = pOrig->iVersion;
  sqlcipher_vfs.pAppData = pOrig;
  sqlcipher_vfs.szOsFile = pOrig->szOsFile + sizeof(sqlcipher_file);
  sqlcipher_vfs.mxPathname = pOrig->mxPathname;

  if((rc = sqlite3_vfs_register(&sqlcipher_vfs, 1)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: error %d occurred registering sqlciphervfs as default", __func__, rc);
  }

end:
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_VFS", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_VFS", __func__);

  return rc;
}

static int sqlcipherOpen(
  sqlite3_vfs *pVfs,
  const char *zName,
  sqlite3_file *pFile,
  int flags,
  int *pOutFlags
){
  sqlcipher_file *p;
  sqlite3_file *pSubFile;
  sqlite3_vfs *pSubVfs;
  sqlcipher_file *open;
  Pager *pPager;
  int rc;


  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS,
    "%s: pVfs=%p,zName=%s,sqlite3_file=%p,flags=%d,pOutFlags=%p", __func__, pVfs, zName, pFile, flags, pOutFlags); 

  p = (sqlcipher_file*)pFile;
  memset(p, 0, sizeof(*p));
  p->name = zName;

  pSubVfs = ORIGVFS(pVfs);
  pSubFile = ORIGFILE(pFile);
  pFile->pMethods = &sqlcipher_io_methods;
  rc = pSubVfs->xOpen(pSubVfs, zName, pSubFile, flags, pOutFlags);
  if( rc ) goto sqlcipher_open_done;

  if (flags & SQLITE_OPEN_MAIN_DB) {
    p->type = SQLCIPHER_DB;

    /* prepend this file to the list of open files */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_VFS", __func__);
    sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_VFS", __func__);

    p->next = sqlcipher_files_open;
    sqlcipher_files_open = p;

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_VFS", __func__);
    sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_VFS", __func__);

  } else if(flags & SQLITE_OPEN_WAL) {
    p->type = SQLCIPHER_WAL;

    /* look up the main db file for the -wal */
    p->main = (sqlcipher_file*) sqlite3_database_file_object(zName); 
    assert( p->main && p->main->main==0 );
    if(!p->main || p->main->main != 0) {
      rc = SQLITE_ERROR;
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: unable to resolve main database for WAL", __func__);
      pSubFile->pMethods->xClose(pSubFile);
      goto sqlcipher_open_done;
    }

  } else if(flags & SQLITE_OPEN_MAIN_JOURNAL) {
    p->type = SQLCIPHER_JOURNAL;

    /* look up the main db file for the -journal */
    p->main = (sqlcipher_file*) sqlite3_database_file_object(zName); 
    assert( p->main && p->main->main==0 );

    if(!p->main || p->main->main != 0) {
      rc = SQLITE_ERROR;
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: unable to resolve main database for JOURNAL", __func__);
      pSubFile->pMethods->xClose(pSubFile);
      goto sqlcipher_open_done;
    }

  } else if(flags & SQLITE_OPEN_SUBJOURNAL) {
    p->type = SQLCIPHER_SUBJOURNAL;

    /* if this is a subjournal, we can't use sqlite3_database_file_object to lookup the main database file.
     * instead, loop through the list of open file handles and attempt to locate one where the pager
     * statment journal file descriptor matches the current file */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: searching for main database for %p", __func__, p);

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_VFS", __func__);
    sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_VFS", __func__);

    open = sqlcipher_files_open;
    while(open) {
      if(open->ctx && (pPager = sqlite3BtreePager(open->ctx->pBt)) && sqlcipher_pager_sjfd(pPager) == pFile) {
        sqlcipher_log(SQLCIPHER_LOG_INFO, SQLCIPHER_LOG_VFS, "%s: this is a SUBJOURNAL for %p, assigning main", __func__, open);
        p->main = open;
        break;
      }
      open = open->next;
    }

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_VFS", __func__);
    sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_VFS", __func__);

    if(!p->main || p->main->main != 0) {
      rc = SQLITE_ERROR;
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: unable to resolve main database for SUBJOURNAL", __func__);
      pSubFile->pMethods->xClose(pSubFile);
      goto sqlcipher_open_done;
    }

  } else {
    p->type = SQLCIPHER_OTHER;
  }

sqlcipher_open_done:
  if( rc ) pFile->pMethods = 0;
  p->init_error = SQLITE_OK;
  return rc;
}


static int sqlcipherClose(sqlite3_file *pFile){
  sqlcipher_file *p = (sqlcipher_file *)pFile;
  sqlcipher_file **ppf;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: pFile=%p, p->name=%s, p->type=%d, p->main=%p, p->ctx=%p",
    __func__, pFile, p->name, p->type, p->main, p->ctx);

  /* delete the current file from the open list */
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_VFS", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_VFS", __func__);

  ppf = &sqlcipher_files_open;

  while(*ppf && *ppf != p) {
    ppf = &((*ppf)->next);
  }

  if(*ppf) {
    *ppf = p->next;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_VFS", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_VFS));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_VFS", __func__);


  /* only free ctx for main database file */
  if(p->ctx) {
    /* wipe and free allocated memory for the context */
    sqlcipher_ctx_free(&p->ctx);
  }

  /* clear main file pointer */
  if(p->main){
    p->main= 0;
  }

  pFile = ORIGFILE(pFile);

  return pFile->pMethods->xClose(pFile);
}

/* Functions for checksum shielding in rollback journals and WAL files
 *
 * SQLite calculates a 4 byte checksum over the page content that is written to rollback
 * journals and an 8 byte checksum for WAL files. Unfortunately, since SQLCipher is now a VFS 
 * (not an inline CODEC) those checksums are calculated over the plaintext of the page data
 * before SQLCipher's encryption happens. Unprotected, the checksums are a plaintext
 * oracle. These functions make a best-effort attempt to protect the checksums before they
 * are written to the journal or wal. 
 * 
 * Since we do not have a place to store additional IVs, tags, etc, this approach uses
 * simple shielding by XORing the bytes of the checksum with a derived key. The key is
 * generated using the provider aead_kbkdf function using a checksum master key
 * (derived at initialization), and then a subkey is derived using a context including the
 * frame / record start offset, and either the journal cksumInit value (which will change
 * for each transaction) or the WAL salt (changing for checkpoint or restart). Both are referred
 * to as salt going forward. 
 *
 * This model provides a reasonable amount of protection for the checksums. The combination of
 * the salt and the offset means that each record's checksum will be encrypted with a distinct
 * key up to 2^16 or 2^32 (birthday bound for the salt and ouput truncation). This will protect
 * the value of the checksum, except cases like the following where it could be possible to
 * detect a many-time-pad:
 *
 * 1. ability to observe multiple snapshots of files (before and after) over time when
 *    record rewrites occur under the same salt (e.g. wal checksum rewrites from rollbacks)
 * 2. observation of a very large corpus of files allowing comparison and discovery of
 *    files with the same salt values
 *
 * Because these would effectively expose different ciphertext checksums encrypted under
 * the same key the protections would be limited in those cases. The practical implications
 * are that:
 *
 * 1. comparisons of checksums under a common key could leak (i.e. plaintext
 *    checksum 0 XOR checksum 1) leaking checksum data (e.g. equality)
 * 2. if the checksum is known in advance, then the key for that salt and record
 *    combination could be recovered entirely, revealing all checksums encrypted
 *    under that subkey
 * 3. if enough samples are collected, statistical recovery of the pad could be possible
 *
 * That said, journal and WAL files have the following properties:
 *
 * 1. they are temporary files frequently deleted or overwritten
 * 2. they are rarely archived
 * 3. it is relatively difficult to observe changes to them "in flight"
 * 4. for WAL specifically, it is extremely difficult to predict
 *    a checksum even for a known plaintext because it is computed
 *    over all previous frames in the file
 *
 * In addition, these checksums are never used for cryptographic integrity. All the actual
 * page data is encrypted with AES-GCM or CBC+HMAC with tag verification. The checksums
 * are never used until after tags are verified, and can't be abused to attack the protections
 * on the actual encrypted data. In other words the absolute worst case is that an attacker
 * who compromised a subkey could confirm plaintext record values (that they already know) or
 * verify guesses of page contents using checksums encrypted under that subkey. 
 *
 * Critically, this level of security is always better, and never worse, than
 * leaving the checksums plaintext.  
 */

static int sqlcipher_shield_journal_cksum(sqlcipher_ctx *ctx, void *zBuf, sqlite_int64 iOfst, int iAmt, i64 record_ofst, u32 cksumInit) {
  int in_record_ofst, cksum_ofst;

  in_record_ofst = (int) (iOfst - record_ofst); /* offset into the current record for operation */
  cksum_ofst = 4 + ctx->page_sz; /* where, in a given rollback journal record, the checksum livs */ 

  if(in_record_ofst == cksum_ofst && iAmt == 4 && ctx->provider->aead_kbkdf) {
    int rc;
    unsigned char k[32];
    unsigned char context[12];

    /* context for kbkdf is cksumInit (changes each transaction) || record_ofst (changes each record)
     * note that this context layout should always be different than that for WAL */
    sqlite3Put4byte(&context[0], cksumInit);
    sqlite3Put4byte(&context[4], (u32)(record_ofst >> 32)); /* high half */
    sqlite3Put4byte(&context[8], (u32)record_ofst); /* low half */

    /* The read and write keys are the same in all cases except for rekey. During a rekey operation
     * read_ctx and write_ctx have different keys, but the journal is always written with the read_key
     * (see sqlite3_rekey-v2 SQLCIPHER_JOURNAL_OP case). Since the journal will always be written with
     * the read key, the checksum should be shielded with it as well. If a rekey succeeds the journal
     * is removed. If a journal is being used for recovery, it would be read with the read key as well */
    sqlcipher_shield(ctx->read_ctx->cksum_key, ctx->key_sz);
    rc = ctx->provider->aead_kbkdf(
      ctx->provider_ctx,
      ctx->read_ctx->cksum_key, ctx->key_sz,
      context, sizeof(context),
      k
    );
    sqlcipher_shield(ctx->read_ctx->cksum_key, ctx->key_sz);

    if(rc != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: aead_kbkdf failed for record at offset %lld %d", __func__, record_ofst, rc);
      return rc;
    }

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: shielding journal record checksum", __func__);
    sqlcipher_xor((unsigned char *) zBuf, 4, k, 4);

    xoshiro_randomness(k, sizeof(k));
  }
  return SQLITE_OK;
}

static int sqlcipher_shield_wal_cksum(sqlcipher_ctx *ctx, void *zBuf, sqlite_int64 iOfst, int iAmt, u32 salt0, u32 salt1){
  sqlite_int64 rel_ofst;
  sqlite_int64 frame_start_ofst;
  int in_frame_ofst;

  if(iOfst < 32) return SQLITE_OK;

  rel_ofst = iOfst - SQLCIPHER_WAL_HDRSIZE; /* offset excluding the header */
  frame_start_ofst = SQLCIPHER_WAL_HDRSIZE + ((rel_ofst / (ctx->page_sz+SQLCIPHER_WAL_FRAME_HDRSIZE)) * (ctx->page_sz+SQLCIPHER_WAL_FRAME_HDRSIZE)); /* where the actual frame starts */
  in_frame_ofst = rel_ofst % (ctx->page_sz + SQLCIPHER_WAL_FRAME_HDRSIZE); /* file offset of the current op into the frame */

  /* The wal checksum is an 8 byte value (2x32-bit) at offset 16 and 20 respectively. Because the header
   * frame header, page size and sector size must all be multiples of 8, a WAL read/write
   * begins and ends on a 8 byte boundary, so the checksum will always be fully contained */

  assert((in_frame_ofst & 7) == 0); /* offset is a multiple of 8 */
  assert((iAmt & 7) == 0); /* amount also a multiple of 8 */
  assert( 
    !(in_frame_ofst < 24 && in_frame_ofst + iAmt > 16) /* does include any bytes in the range 16-24 */
    || (in_frame_ofst <= 16 && in_frame_ofst + iAmt >= 24) /* includes all the bytes in the range 16-24 */
  ); 

  if(in_frame_ofst <= 16 && in_frame_ofst + iAmt >= 24 && ctx->provider->aead_kbkdf) { /* operation spans the checksum bytes */
    /* checksum starts 16 bytes into the each frame. If the in frame offset of the zBuf is 8, then
     * we must subtract that from 16 to get the position in zBuf for the checksum. The same stands for 0 and 16,
     * which are the only other 8-byte aligned values that will fall through into this block */
    unsigned char k[32];
    unsigned char context[12];
    int rc;
    u32 frame_idx = (u32)(rel_ofst / (ctx->page_sz + SQLCIPHER_WAL_FRAME_HDRSIZE)); /* the sequential index of this frame in the wal */

    /* context for kbkdf is salt0 (incremented on restart) || salt1 (random per WAL) || frame_idx (changes each frame) 
     * note that this context layout should always be different than that for journal files */
    sqlite3Put4byte(&context[0], salt0);
    sqlite3Put4byte(&context[4], salt1);
    sqlite3Put4byte(&context[8], frame_idx);

    /* The read and write keys are the same in all cases except for rekey, which forces the journal mode
     * to DELETE on the database before re-encrypting. This means that the read and write key are identical
     * and we just use the former for consistency with the journal code above. */
    sqlcipher_shield(ctx->read_ctx->cksum_key, ctx->key_sz);
    rc = ctx->provider->aead_kbkdf(
      ctx->provider_ctx,
      ctx->read_ctx->cksum_key, ctx->key_sz,
      context, sizeof(context),
      k
    );
    sqlcipher_shield(ctx->read_ctx->cksum_key, ctx->key_sz);

    if(rc != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: aead_kbkdf failed for frame at %lld %d", __func__, frame_start_ofst, rc);
      return rc;
    }

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: shielding WAL frame checksum", __func__);
    sqlcipher_xor(((unsigned char *) zBuf) + (16 - in_frame_ofst), 8, k, 8);

    xoshiro_randomness(k, sizeof(k));
  }
  return SQLITE_OK;
}


static int sqlcipher_read_db(
  sqlite3_file *pFile, 
  void *zBuf, 
  int iAmt, 
  sqlite_int64 iOfst,
  sqlcipher_ctx *ctx
) {
  int rc;
  Pgno page = 0;
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  void *buf = zBuf;
  sqlite3_int64 start = iOfst;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, 
    "%s: fd=%p,zBuf=%p,iAmt=%d,iOfst=%lld,ctx=%p,ctx->page_size=%d",
    __func__, fd, zBuf, iAmt, iOfst, ctx, ctx->page_sz);

  /* sqlcipher will perform a direct read on the first 16 bytes of the database to load the database salt, and that
     read operation must pass through directly without undergoing any modification (e.g. conversion to "SQLite Format 3\n" */
  if(iOfst == 0 && iAmt == 16) {
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: DB magic header string (salt) passthrough", __func__);
    rc = subfd->pMethods->xRead(subfd, zBuf, iAmt, iOfst);
    goto end;
  }

  /* SQLite will frequently direct read bytes from the header without the rest of the first page. An example is when reading the
   * databae file version which occurs every time the database is locked to make sure it hasn't been modified by another process.
   * It is extremely expensive to read the entire first page and decrypt it every time. Therefore, sqlcipher_file maintains
   * a cache of the header in both plaintext and encrypted form. When a request is made to short read bytes from the header, we
   * read the current encrypted header directly from the file and compare it to the cached encrypted bytes. If they match, we know the
   * header has not been modified, and we can serve the appropriate bytes from the plaintext cache without a full page read and
   * decryption operation. If there is not match, then the file has changed on disk and we'll re-read the entire page and decrypt it */
  if(iOfst + iAmt <= SQLCIPHER_DB_HDRSIZE) {
    unsigned char header[SQLCIPHER_DB_HDRSIZE];

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: direct file header read at iOfst %lld iAmt %d", __func__, iOfst, iAmt);

    if((rc = subfd->pMethods->xRead(subfd, header, SQLCIPHER_DB_HDRSIZE, 0)) == SQLITE_OK && memcmp(header, fd->eheader, SQLCIPHER_DB_HDRSIZE) == 0) {
      sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: using cached header data", __func__);
      memcpy(zBuf, fd->header+iOfst, iAmt);
      goto end;
    }

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: file changed (header mismatch), rereading page", __func__);
  }

  /* in the case of a direct partial read, i.e. to the database header in the event of a mismatch, read and decrypt the
   * entire page and then only return the subset of the data that the caller requested */
  if(iAmt != ctx->page_sz) {

    /* verify that a read operation never attempts to span multiple pages which would overrun the page_data buffer */
    assert(!((iOfst % ctx->page_sz) + iAmt > ctx->page_sz));
    if((iOfst % ctx->page_sz) + iAmt > ctx->page_sz) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: illegal read spanning multiple pages at iOfst=%lld iAmt=%d", __func__, iOfst, iAmt);
      rc = SQLITE_IOERR_READ;
      goto end;
    }

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: short read from iOfst %lld iAmt %d", __func__, iAmt, iOfst);
    buf = ctx->page_data; /* zBuf is too small to hold a full page, use context page data temp store for contents */
    start = (iOfst / ctx->page_sz) * ctx->page_sz; /* calculate the starting point for the full page read */
  }

  /* main db always consists of complete pages, numbered starting at 1 (the header is part of the first page) */
  page = (iOfst/ctx->page_sz)+1;

  rc = subfd->pMethods->xRead(subfd, buf, ctx->page_sz, start);

  if (rc == SQLITE_IOERR_SHORT_READ) {
    sqlcipher_memset(zBuf, 0, iAmt);
    goto end; /* legitimate short read (i.e. from a file that does not exist yet), no error log and return result to caller */
  } else if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error for page %d iOfst %lld: %d", __func__, page, iOfst, rc);
    goto end;
  }

  if(page == 1) { /* update encrypted copy of db header prior to decryption any time page 1 is read */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: updating cached encrypted header", __func__);
    memcpy(fd->eheader, buf, SQLCIPHER_DB_HDRSIZE);
  }

  sqlcipher_process_page(ctx, buf, page, SQLCIPHER_READ_OP, &rc); /* decrypt page */
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: error %d processing page %d", __func__, rc, page);
    sqlcipher_memset(fd->eheader, 0, SQLCIPHER_DB_HDRSIZE);
    sqlcipher_memset(fd->header, 0, SQLCIPHER_DB_HDRSIZE);
    goto end;
  }

  if(page == 1) { /* update plaintext copy of db header after decryption any time page 1 is read */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: updating cached plaintext header", __func__);
    memcpy(fd->header, buf, SQLCIPHER_DB_HDRSIZE);
  }

  if(iAmt != ctx->page_sz) {
    /* copy the data back from the temp buffer over to the caller's buffer */
    memcpy(zBuf, ((unsigned char *)buf) + (iOfst % ctx->page_sz), iAmt);
  }

end:
  return rc; 
}

static int sqlcipher_read_journal(
  sqlite3_file *pFile, 
  void *zBuf, 
  int iAmt, 
  sqlite_int64 iOfst,
  sqlcipher_ctx *ctx,
  int is_main_journal
) {
  int rc;
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  unsigned char pgno_raw[4];
  Pgno page = 0;


  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, 
    "%s: fd=%p,zBuf=%p,iAmt=%d,iOfst=%lld,ctx=%p,ctx->page_size=%d",
    __func__, fd, zBuf, iAmt, iOfst, ctx, ctx->page_sz);


  if (iOfst == 0 || iAmt != ctx->page_sz) { /* either the initial journal header, or not a full page */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: optimized JOURNAL read passthrough", __func__);
    rc = subfd->pMethods->xRead(subfd, zBuf, iAmt, iOfst);
    if(rc == SQLITE_OK && is_main_journal) {
      Pager *pPager = sqlite3BtreePager(ctx->pBt); 
     
      /* pPager->journalOff has already been advanced to the end of the record at the time
       * this read occurs, so back it off to the start of the page. see pager.c:pager_playback_one_page
       * and it's caller pager.c:pager_playback */
      rc = sqlcipher_shield_journal_cksum(ctx, zBuf, iOfst, iAmt, sqlcipher_pager_journalOff(pPager) - 4 - ctx->page_sz - 4, sqlcipher_pager_cksumInit(pPager));
    }
    return rc; 
  }

  /* this is a full page read, first read the page number directly */ 
  if((rc = subfd->pMethods->xRead(subfd, &pgno_raw, 4, iOfst-4)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error for JOURNAL page number at offset %lld: %d", __func__, iOfst-4, rc);
    return rc;
  }
  page = sqlite3Get4byte(pgno_raw);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: JOURNAL read for page %d", __func__, page);

  if((rc = subfd->pMethods->xRead(subfd, zBuf, ctx->page_sz, iOfst)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error: %d", __func__, rc);
    return rc;
  }

  sqlcipher_process_page(ctx, zBuf, page, SQLCIPHER_READ_OP, &rc);
  if(rc != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: error %d processing page %d", __func__, rc, page);
  }

  return rc;
}

static int sqlcipher_read_wal(
  sqlite3_file *pFile, 
  void *zBuf, 
  int iAmt, 
  sqlite_int64 iOfst,
  sqlcipher_ctx *ctx
) {
  int rc;
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  unsigned char pgno_raw[4];
  Pgno page = 0;
  Pager *pPager = sqlite3BtreePager(ctx->pBt); 
  
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, 
    "%s: fd=%p,zBuf=%p,iAmt=%d,iOfst=%lld,ctx=%p,ctx->page_size=%d",
    __func__, fd, zBuf, iAmt, iOfst, ctx, ctx->page_sz);

  /* only intercept reads of full wal frames or wal header+wal frame */
  if(iAmt == ctx->page_sz) {
    /* direct read for a page data from a wal frame */

    /* each WAL frame has a 24 byte header before the actual page data which is written
     * to the WAL file prior to the WAL frame data. Extract the first 4 bytes of the frame header to determine
     * what page we are reading. This is required to ensure that the special handling for the first
     * database page is respected */
    if((rc = subfd->pMethods->xRead(subfd, &pgno_raw, 4, iOfst-SQLCIPHER_WAL_FRAME_HDRSIZE)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error for WAL page number at offset %lld: %d", __func__, iOfst-SQLCIPHER_WAL_FRAME_HDRSIZE, rc);
      return rc;
    }
    page = sqlite3Get4byte(pgno_raw);

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: WAL page-only read for page %d", __func__, page);

    if((rc = subfd->pMethods->xRead(subfd, zBuf, ctx->page_sz, iOfst)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error: %d", __func__, rc);
      return rc;
    }

    sqlcipher_process_page(ctx, zBuf, page, SQLCIPHER_READ_OP, &rc);
    if(rc != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: error %d processing page %d", __func__, rc, page);
    }

    return rc;

  } else if (iAmt == ctx->page_sz + SQLCIPHER_WAL_FRAME_HDRSIZE) {
    /* full read of a wal frame including the frame header */
    if((rc = subfd->pMethods->xRead(subfd, zBuf, iAmt, iOfst)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: WAL full frame xRead returned error: %d", __func__, rc);
      return rc;
    }

    page = sqlite3Get4byte(zBuf); /* first four bytes is frame header page number */

    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: WAL full-frame read for page %d", __func__, page);

    sqlcipher_process_page(ctx, ((unsigned char*) zBuf) + SQLCIPHER_WAL_FRAME_HDRSIZE, page, SQLCIPHER_READ_OP, &rc); /* following bytes are page data itself, offset for header */

    if(rc != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: error %d processing page %d", __func__, rc, page);
      return rc;
    }

    /* this read includes a frame header, decrypt the checksum */
    return sqlcipher_shield_wal_cksum(ctx, zBuf, iOfst, iAmt, sqlcipher_pager_wal_salt(pPager, 0), sqlcipher_pager_wal_salt(pPager, 1));
  }

  rc = subfd->pMethods->xRead(subfd, zBuf, iAmt, iOfst);
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: optimized WAL header read passthrough", __func__);

  /* short / passthrough read also may require checksum decrypt */
  if(rc == SQLITE_OK)
    rc = sqlcipher_shield_wal_cksum(ctx, zBuf, iOfst, iAmt, sqlcipher_pager_wal_salt(pPager, 0), sqlcipher_pager_wal_salt(pPager, 1));
   
  return rc;
}

static int sqlcipherRead(
  sqlite3_file *pFile, 
  void *zBuf, 
  int iAmt, 
  sqlite_int64 iOfst
){
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  sqlcipher_ctx *ctx = fd->main ? fd->main->ctx : fd->ctx;

  /* if a context initialization failed, block all operations */
  if(fd->init_error != SQLITE_OK) return SQLITE_IOERR;

  if(!ctx || SQLCIPHER_FLAG_GET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_READ) || fd->type == SQLCIPHER_OTHER) {
    /* direct read w/o decryption when no context attached or full passthrough enabled */ 
    return subfd->pMethods->xRead(subfd, zBuf, iAmt, iOfst);
  } else if (fd->type == SQLCIPHER_JOURNAL) {
    return sqlcipher_read_journal(pFile, zBuf, iAmt, iOfst, ctx, 1);
  } else if (fd->type == SQLCIPHER_SUBJOURNAL) { 
    return sqlcipher_read_journal(pFile, zBuf, iAmt, iOfst, ctx, 0);
  } else if (fd->type == SQLCIPHER_WAL) {
    return sqlcipher_read_wal(pFile, zBuf, iAmt, iOfst, ctx);
  }

  /* fd->type == SQLCIPHER_DB */
  return sqlcipher_read_db(pFile, zBuf, iAmt, iOfst, ctx);
}

static int sqlcipher_write_db(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst,
  sqlcipher_ctx *ctx
){
  int rc = SQLITE_OK;
  void *b = (void *) zBuf;
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  Pgno page = (iOfst/ctx->page_sz)+1; /* main db always consists of complete pages, the header is considered to be part of the first page */ 

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, 
    "%s: fd=%p,zBuf=%p,iAmt=%d,iOfst=%lld,ctx=%p,ctx->page_size=%d",
    __func__, fd, zBuf, iAmt, iOfst, ctx, ctx->page_sz);

  /* writes to the main database should always be in page size blocks */
  if(iAmt != ctx->page_sz) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: invalid write request for non-page size block %d", __func__, iAmt);
    rc = SQLITE_IOERR;
    goto error;
  }

  if(page == 1) { /* update the plaintext cached header before encrypting the page any time page 1 is written */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: caching plaintext file header", __func__);
    memcpy(fd->header, b, SQLCIPHER_DB_HDRSIZE);
  }

  if(!(b = sqlcipher_process_page(ctx, b, page, SQLCIPHER_WRITE_OP, &rc))) {
    assert(rc != SQLITE_OK);
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: sqlcipher_process_page error occured omitting write: %d", __func__, rc);
    goto error;
  }
  assert(rc == SQLITE_OK);

  if((rc = subfd->pMethods->xWrite(subfd, b, iAmt, iOfst)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xWrite returned error for database page %d at offset %lld: %d", __func__, page, iOfst, rc);
    goto error;
  }

  if(page == 1) { /* update the encrypted cached header after the page any time page 1 is written */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: caching encrypted file header", __func__);
    memcpy(fd->eheader, b, SQLCIPHER_DB_HDRSIZE);
  }

  goto end;

error:
  /* if any error occurs encrypting or writing the first page, wipe the cached header data so that it would never be used */
  if(page == 1) {
    memset(fd->header, 0, SQLCIPHER_DB_HDRSIZE);
    memset(fd->eheader, 0, SQLCIPHER_DB_HDRSIZE);
  }

end:
  return rc;
}

static int sqlcipher_write_journal(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst,
  sqlcipher_ctx *ctx,
  int is_main_journal
){
  int rc = SQLITE_OK;
  void *b = (void *) zBuf;
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  unsigned char pgno_raw[4];
  Pgno page = 0;
  Pager *pPager = sqlite3BtreePager(ctx->pBt);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, 
    "%s: fd=%p,zBuf=%p,iAmt=%d,iOfst=%lld,ctx=%p,ctx->page_size=%d",
    __func__, fd, zBuf, iAmt, iOfst, ctx, ctx->page_sz);


  if(is_main_journal) {
    /* pPager->journalOff is the start of the current record when the write occurs
     * see pager.c:pagerAddPageToRollbackJournal */
    if((rc = sqlcipher_shield_journal_cksum(ctx, b, iOfst, iAmt, sqlcipher_pager_journalOff(pPager), sqlcipher_pager_cksumInit(pPager))) != SQLITE_OK) {
      return rc;
    }
  }
 
  if (iOfst == 0 || iAmt != ctx->page_sz) { /* either the initial journal header, or not a full page */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: optimized JOURNAL write passthrough", __func__);
    return subfd->pMethods->xWrite(subfd, zBuf, iAmt, iOfst);
  } 

  if(is_main_journal) {
    i64 header_ofst = sqlcipher_pager_journalHdr(pPager); /* current position of journalHeader */
    u32 header_sz = sqlcipher_pager_sectorSize(pPager); /* journal header is always sector sized */ 
  
    /* any sector-aligned full-page write must occur inside the current header */
    assert((iOfst % header_sz != 0) || (iOfst >= header_ofst && iOfst < header_ofst + header_sz));

    if(iOfst >= header_ofst && iOfst < header_ofst + header_sz) {
      /* write to the main journal inside the current journal header */
      sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: optimized JOURNAL write passthrough for main journal header write (header_sz = %u)", __func__, header_sz);
      return subfd->pMethods->xWrite(subfd, zBuf, iAmt, iOfst);
    }
  }

  /* standard page write needs to first read the page number store in the 4 bytes immediately before the page data */
  if((rc = subfd->pMethods->xRead(subfd, &pgno_raw, 4, iOfst-4)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error for JOURNAL page number at offset %lld: %d", __func__, iOfst-4, rc);
    return rc;
  }

  page = sqlite3Get4byte(pgno_raw);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: JOURNAL write for page %d", __func__, page);
  if(!(b = sqlcipher_process_page(ctx, b, page, SQLCIPHER_JOURNAL_OP, &rc))) {
    assert(rc != SQLITE_OK);
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: sqlcipher_process_page error occured omitting write: %d", __func__, rc);
    return rc;
  }
  assert(rc == SQLITE_OK);
  return subfd->pMethods->xWrite(subfd, b, iAmt, iOfst);
}

static int sqlcipher_write_wal(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst,
  sqlcipher_ctx *ctx
){
  int rc = SQLITE_OK;
  void *b = (void *) zBuf;
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  unsigned char pgno_raw[4];
  Pgno page = 0;
  unsigned char *temp_page = NULL;
  sqlite_int64 startOfst = iOfst;
  sqlite_int64 pageOfst = 0;
  int sync = 0;
  sqlite_int64 rel_ofst, frame_start_ofst;
  int in_frame_ofst;
  Pager *pPager = sqlite3BtreePager(ctx->pBt); 
 
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, 
    "%s: fd=%p,zBuf=%p,iAmt=%d,iOfst=%lld,ctx=%p,ctx->page_size=%d",
    __func__, fd, zBuf, iAmt, iOfst, ctx, ctx->page_sz);

  if(iOfst < SQLCIPHER_WAL_HDRSIZE) {
    /* this is a write of the wal header, allow it to pass through */
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: optimized WAL header write passthrough", __func__);
    return subfd->pMethods->xWrite(subfd, zBuf, iAmt, iOfst);
  } 

  rel_ofst = iOfst - SQLCIPHER_WAL_HDRSIZE; /* offset excluding the header */
  frame_start_ofst = SQLCIPHER_WAL_HDRSIZE + ((rel_ofst / (ctx->page_sz+SQLCIPHER_WAL_FRAME_HDRSIZE)) * (ctx->page_sz+SQLCIPHER_WAL_FRAME_HDRSIZE)); /* where the actual frame starts */
  in_frame_ofst = rel_ofst % (ctx->page_sz + SQLCIPHER_WAL_FRAME_HDRSIZE); /* offset of the current write into the frame */

  if((rc = sqlcipher_shield_wal_cksum(ctx, b, iOfst, iAmt, sqlcipher_pager_wal_salt(pPager, 0), sqlcipher_pager_wal_salt(pPager, 1))) != SQLITE_OK) { 
    return rc;
  }

  /* if the writing to the frame header (whole or split), write pasthrough */ 
  if (in_frame_ofst < 24) {
   sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: WAL frame header write passthrough", __func__);
   return subfd->pMethods->xWrite(subfd, zBuf, iAmt, iOfst);
  }

  /* now writing page data, outside the WAL header or the frame header. from here on
   * all operations in sqlcipher_write_wal will be relative to startOfst, instead of iOft. startOfst may be adjusted
   * for partial page writes */

  if(iAmt != ctx->page_sz) {
    /* WAL writes will not always occur in full blocks. When PSOW=0 or synchronous=FULL page data may be written in multiple chunks.
     * if an iAmt is requested that is smaller than page_size, then an attempted split write is occurring (see wal.c:walFrames)
     * we still need to write a full page, but zBuf might not be big enough to hold it. attempt to read the existing
     * partial page, decrypt it, update it, the writ write it. Allocate a
     * temporary storage space for the full page to do so */

    startOfst = frame_start_ofst + SQLCIPHER_WAL_FRAME_HDRSIZE; /* the actual start of the page data */
    pageOfst = iOfst - startOfst;  /* offset inside the page */
    
    sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS,
      "%s: WAL padding write iOfst=%d, iAmt=%d, startOfst=%lld, newOfst=%lld", __func__, iOfst, iAmt, startOfst, pageOfst);

    /* write requests for more than one page worth of data are not permitted. */
    if(pageOfst + iAmt > ctx->page_sz) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: invalid WAL write request %lld %d", __func__, pageOfst, iAmt);
      rc = SQLITE_IOERR;
      goto end;
    }

    if(!(temp_page = sqlcipher_malloc(ctx->page_sz))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: unable to allocate temporary page space", __func__);
      rc = SQLITE_NOMEM;
      goto end;
    }

    /* each WAL frame has a 24 byte header before the actual page data which is written
     * to the WAL file prior to the WAL frame data. Extract the first 4 bytes of the frame header to determine
     * what the page we are writing. */
    if((rc = subfd->pMethods->xRead(subfd, &pgno_raw, 4, startOfst-SQLCIPHER_WAL_FRAME_HDRSIZE)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error for WAL page number at offset %lld: %d", __func__, startOfst-SQLCIPHER_WAL_FRAME_HDRSIZE, rc);
      goto end;
    }
    page = sqlite3Get4byte(pgno_raw);

    if(pageOfst == 0) {
      /* this is the initial write of split page data when the wal file is being padded to a sector boundry. */
      memcpy(temp_page, zBuf, iAmt);
    } else {
      /* some portion of this frame page data has already been written. read back the existing portion
       * apply an inline update. this is the secondary write of the padding data. */

      if((rc = subfd->pMethods->xRead(subfd, temp_page, ctx->page_sz, startOfst)) != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: WAL padding write read at offset %lld failed: %d", __func__, startOfst, rc);
        goto end;
      }
      sqlcipher_process_page(ctx, temp_page, page, SQLCIPHER_READ_OP, &rc); /* decrypt existing data */
      if(rc != SQLITE_OK) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: error %d processing page %d", __func__, rc, page);
        goto end;
      }

      memcpy(temp_page + pageOfst, zBuf, iAmt);

      /* The WAL has already been synced at this point after the
       * previous partial write. however, since a partial write is occuring that means that frame is crossing a sector boundry. If the
       * part over the sector boundry became corrupt it would invalidate the last page and cause corruption. therefore in this specific
       * condition we will trigger a final fsync again after the frame is written */
      sync = 1;
    }
    b = temp_page;
  } else {
    /* this is a full page WAL write. just lookup the page number */
    if((rc = subfd->pMethods->xRead(subfd, &pgno_raw, 4, startOfst-SQLCIPHER_WAL_FRAME_HDRSIZE)) != SQLITE_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xRead returned error for WAL page number at offset %lld: %d", __func__, startOfst-SQLCIPHER_WAL_FRAME_HDRSIZE, rc);
      goto end;
    }
    page = sqlite3Get4byte(pgno_raw);
  }
 
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_VFS, "%s: WAL write for page %d", __func__, page);
 
  
  if(!(b = sqlcipher_process_page(ctx, b, page, SQLCIPHER_WRITE_OP, &rc))) { /* (re)encrypt data */ 
    assert(rc != SQLITE_OK);
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: sqlcipher_process_page error occured omitting write: %d", __func__, rc);
    goto end;
  }
  assert(rc == SQLITE_OK);

  if((rc = subfd->pMethods->xWrite(subfd, b, ctx->page_sz, startOfst)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_VFS, "%s: xWrite error: %d", __func__, rc);
    goto end;
  }

  if(sync) {
    rc = subfd->pMethods->xSync(subfd, SQLITE_SYNC_DATAONLY | SQLITE_SYNC_FULL); /* resync for the final frame for a partial write*/
  }

end:
  if(temp_page) sqlcipher_free(temp_page, ctx->page_sz);
  return rc;
}

static int sqlcipherWrite(
  sqlite3_file *pFile,
  const void *zBuf,
  int iAmt,
  sqlite_int64 iOfst
){
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  sqlcipher_ctx *ctx = fd->main ? fd->main->ctx : fd->ctx;

  /* if a context initialization failed, block all operations */
  if(fd->init_error != SQLITE_OK) return SQLITE_IOERR;

  if(!ctx || SQLCIPHER_FLAG_GET(fd->flags, SQLCIPHER_FILE_PASSTHROUGH_WRITE) || fd->type == SQLCIPHER_OTHER) {
    /* direct write w/o encryption when no context attached or full passthrough enabled */ 
    return subfd->pMethods->xWrite(subfd, zBuf, iAmt, iOfst);
  } else if (fd->type == SQLCIPHER_JOURNAL) {
    return sqlcipher_write_journal(pFile, zBuf, iAmt, iOfst, ctx, 1);
  } else if (fd->type == SQLCIPHER_SUBJOURNAL) {
    return sqlcipher_write_journal(pFile, zBuf, iAmt, iOfst, ctx, 0);
  } else if (fd->type == SQLCIPHER_WAL) {
    return sqlcipher_write_wal(pFile, zBuf, iAmt, iOfst, ctx);
  } 
  
  /* fd->type == SQLCIPHER_DB */
  return sqlcipher_write_db(pFile, zBuf, iAmt, iOfst, ctx);
}

static int sqlcipherDeviceCharacteristics(sqlite3_file *pFile){
  pFile = ORIGFILE(pFile);
  int ch = pFile->pMethods->xDeviceCharacteristics(pFile); 
  /* unset SUBPAGE_READ to prevent SQLite from doing direct unaligned
     reads from pages, for example when fetching content from an
     overflow page. */
  SQLCIPHER_FLAG_UNSET(ch, SQLITE_IOCAP_SUBPAGE_READ);
  return ch;
}

static int sqlcipherTruncate(sqlite3_file *pFile, sqlite_int64 size){
  pFile = ORIGFILE(pFile);
  return pFile->pMethods->xTruncate(pFile, size);
}

static int sqlcipherSync(sqlite3_file *pFile, int flags){
  pFile = ORIGFILE(pFile);
  return pFile->pMethods->xSync(pFile, flags);
}

static int sqlcipherFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
  sqlcipher_file *p = (sqlcipher_file *)pFile;
  pFile = ORIGFILE(p);
  return pFile->pMethods->xFileSize(pFile, pSize);
}

static int sqlcipherLock(sqlite3_file *pFile, int eLock){
  pFile = ORIGFILE(pFile);
  return pFile->pMethods->xLock(pFile, eLock);
}

static int sqlcipherUnlock(sqlite3_file *pFile, int eLock){
  pFile = ORIGFILE(pFile);
  return pFile->pMethods->xUnlock(pFile, eLock);
}

static int sqlcipherCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  pFile = ORIGFILE(pFile);
  return pFile->pMethods->xCheckReservedLock(pFile, pResOut);
}

static int sqlcipherFileControl(sqlite3_file *pFile, int op, void *pArg){
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  sqlcipher_ctx *ctx = fd->main ? fd->main->ctx : fd->ctx;

  if (op == SQLITE_FCNTL_PRAGMA) {
    char **args = (char**)pArg;
    const char *name = args[1];
    const char *val  = args[2];

    if( sqlite3_stricmp(name, "cipher_status")== 0 && !val){
      if(ctx && ctx->error == SQLITE_OK) {
        args[0] = sqlite3_mprintf("%d", 1);
      } else {
        args[0] = sqlite3_mprintf("%d", 0);
      }
      return SQLITE_OK;
    } else
    if( sqlite3_stricmp(name, "cipher_fips_status")== 0 && !val && ctx ){
      args[0] = sqlite3_mprintf("%d", ctx->provider->fips_status(ctx->provider_ctx)); 
      return SQLITE_OK;
    }
  }
  return subfd->pMethods->xFileControl(subfd, op, pArg);
}

static int sqlcipherSectorSize(sqlite3_file *pFile){
  /* sector size is the "blast radius" for torn pages. protection is provided
   * by SQLite itself, and with SQLCipher the additonal AEAD protections. In practice
   * we can't change this with SQLCipher because sector size is calculated when the
   * file is opened, which is prior to keying. If this were to report a different
   * value post-key, it would case a skew with WAL which queries later. So we
   * defer this to the underlying VFS in all cases. */
  pFile = ORIGFILE(pFile);
  return pFile->pMethods->xSectorSize(pFile);
}

/* x*Shm* VFS functions are only supported in VFS version 2+. SQLCipher will always
 * report as a V3 VFS, so these methods check if the underlying VFS is of a lower
 * version than necessary and if so will error out (https://www.sqlite.org/c3ref/io_methods.html) */
static int sqlcipherShmMap(
  sqlite3_file *pFile,
  int iPg,
  int pgsz,
  int bExtend,
  void volatile **pp
){
  pFile = ORIGFILE(pFile);
  if( pFile->pMethods->iVersion<2 || !pFile->pMethods->xShmMap ) return SQLITE_IOERR_SHMMAP;
  return pFile->pMethods->xShmMap(pFile,iPg,pgsz,bExtend,pp);
}

static int sqlcipherShmLock(sqlite3_file *pFile, int offset, int n, int flags){
  pFile = ORIGFILE(pFile);
  if( pFile->pMethods->iVersion<2 || !pFile->pMethods->xShmLock ) return SQLITE_IOERR_SHMLOCK;
  return pFile->pMethods->xShmLock(pFile,offset,n,flags);
}

static void sqlcipherShmBarrier(sqlite3_file *pFile){
  pFile = ORIGFILE(pFile);
  if( pFile->pMethods->iVersion<2 || !pFile->pMethods->xShmBarrier ) return;
  pFile->pMethods->xShmBarrier(pFile);
}

static int sqlcipherShmUnmap(sqlite3_file *pFile, int deleteFlag){
  pFile = ORIGFILE(pFile);
  if( pFile->pMethods->iVersion<2 || !pFile->pMethods->xShmUnmap ) return SQLITE_IOERR_SHMMAP;
  return pFile->pMethods->xShmUnmap(pFile,deleteFlag);
}

/* xFetch and xUnfetch are only supported by VFS version 3+. SQLCipher will
 * always report as V3, so these methods check both the underlying VFS
 * version and also that we are dealing with a plaintext database
 * before handing off. */
static int sqlcipherFetch(
  sqlite3_file *pFile,
  sqlite3_int64 iOfst,
  int iAmt,
  void **pp
){
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  sqlcipher_ctx *ctx = fd->main ? fd->main->ctx : fd->ctx;

  /* Only support mmap if a sqlcipher_ctx is not attached at this point. If we
   * allowed direct fetch it would bypass the VFS read decryption. Per the
   * SQLite documentation, if a call to xFetch() returns a NULL Pointer
   * then it will fall back on xRead() which is what we want. */
  if( !ctx && subfd->pMethods->iVersion>2 && subfd->pMethods->xFetch ){
    return subfd->pMethods->xFetch(subfd, iOfst, iAmt, pp);
  }
  *pp = 0;
  return SQLITE_OK;
}

static int sqlcipherUnfetch(sqlite3_file *pFile, sqlite3_int64 iOfst, void *pPage){
  sqlcipher_file *fd = (sqlcipher_file *)pFile;
  sqlite3_file *subfd = ORIGFILE(pFile);
  sqlcipher_ctx *ctx = fd->main ? fd->main->ctx : fd->ctx;

  if(ctx) return SQLITE_IOERR; /* Unfetch should never be called for an encrypted database */

  if( subfd->pMethods->iVersion>2 && subfd->pMethods->xUnfetch ){
    return subfd->pMethods->xUnfetch(subfd, iOfst, pPage);
  }
  return SQLITE_OK;
}

static int sqlcipherDelete(sqlite3_vfs *pVfs, const char *zPath, int dirSync){
  return ORIGVFS(pVfs)->xDelete(ORIGVFS(pVfs), zPath, dirSync);
}
static int sqlcipherAccess(
  sqlite3_vfs *pVfs, 
  const char *zPath, 
  int flags, 
  int *pResOut
){
  return ORIGVFS(pVfs)->xAccess(ORIGVFS(pVfs), zPath, flags, pResOut);
}
static int sqlcipherFullPathname(
  sqlite3_vfs *pVfs, 
  const char *zPath, 
  int nOut, 
  char *zOut
){
  return ORIGVFS(pVfs)->xFullPathname(ORIGVFS(pVfs),zPath,nOut,zOut);
}
static void *sqlcipherDlOpen(sqlite3_vfs *pVfs, const char *zPath){
  return ORIGVFS(pVfs)->xDlOpen(ORIGVFS(pVfs), zPath);
}
static void sqlcipherDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
  ORIGVFS(pVfs)->xDlError(ORIGVFS(pVfs), nByte, zErrMsg);
}
static void (*sqlcipherDlSym(sqlite3_vfs *pVfs, void *p, const char *zSym))(void){
  return ORIGVFS(pVfs)->xDlSym(ORIGVFS(pVfs), p, zSym);
}
static void sqlcipherDlClose(sqlite3_vfs *pVfs, void *pHandle){
  ORIGVFS(pVfs)->xDlClose(ORIGVFS(pVfs), pHandle);
}
static int sqlcipherRandomness(sqlite3_vfs *pVfs, int nByte, char *zBufOut){
  return ORIGVFS(pVfs)->xRandomness(ORIGVFS(pVfs), nByte, zBufOut);
}
static int sqlcipherSleep(sqlite3_vfs *pVfs, int nMicro){
  return ORIGVFS(pVfs)->xSleep(ORIGVFS(pVfs), nMicro);
}
static int sqlcipherCurrentTime(sqlite3_vfs *pVfs, double *pTimeOut){
  return ORIGVFS(pVfs)->xCurrentTime(ORIGVFS(pVfs), pTimeOut);
}
static int sqlcipherGetLastError(sqlite3_vfs *pVfs, int a, char *b){
  return ORIGVFS(pVfs)->xGetLastError(ORIGVFS(pVfs), a, b);
}
static int sqlcipherCurrentTimeInt64(sqlite3_vfs *pVfs, sqlite3_int64 *p){
  sqlite3_vfs *pOrig = ORIGVFS(pVfs);
  int rc;
  assert( pOrig->iVersion>=2 );
  if( pOrig->xCurrentTimeInt64 ){
    rc = pOrig->xCurrentTimeInt64(pOrig, p);
  }else{
    double r;
    rc = pOrig->xCurrentTime(pOrig, &r);
    *p = (sqlite3_int64)(r*86400000.0);
  }
  return rc;
}
static int sqlcipherSetSystemCall(
  sqlite3_vfs *pVfs,
  const char *zName,
  sqlite3_syscall_ptr pCall
){
  return ORIGVFS(pVfs)->xSetSystemCall(ORIGVFS(pVfs),zName,pCall);
}
static sqlite3_syscall_ptr sqlcipherGetSystemCall(
  sqlite3_vfs *pVfs,
  const char *zName
){
  return ORIGVFS(pVfs)->xGetSystemCall(ORIGVFS(pVfs),zName);
}
static const char *sqlcipherNextSystemCall(sqlite3_vfs *pVfs, const char *zName){
  return ORIGVFS(pVfs)->xNextSystemCall(ORIGVFS(pVfs), zName);
}

#ifdef SQLCIPHER_TEST
/* it is sometimes difficult to test sqlcipher internals from the TCL test suite, so this
 * function will provide a minimal hook to execute some simple internal testing. It can execute
 * any internal tests, for each that fails, it will output a row to the result set. Then the
 * TCL test will be able to call it via PRAGMA cipher_selftest. The TCL test will call this
 * as the last test. Note that ordering matters here, so its important that any tests define
 * leave things in a sane state for further tests. */
void sqlcipher_selftest(sqlite3* db, Parse *pParse) {
 /* implementation left empty for future use */
}
#endif /* SQLCIPHER_TEST */

#endif
/* END SQLCIPHER */

