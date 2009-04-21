/* 
** SQLite Cipher
** crypto.h developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** Copyright (c) 2008, ZETETIC LLC
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
#if SQLITE_HAS_CODEC
#ifndef CRYPTO_H
#define CRYPTO_H

#define FILE_HEADER_SZ 16

#define CIPHER EVP_aes_256_cfb()
#define CIPHER_DECRYPT 0
#define CIPHER_ENCRYPT 1

#define HMAC_HASH EVP_sha256()
#define SHA_DIGEST_LENGTH 32

#ifndef PBKDF2_SALT
#define PBKDF2_SALT {0x99, 0x76, 0x93, 0x7a, 0xc7, 0x2e, 0xd3, 0x88} 
#endif 

#ifndef PBKDF2_SALT_SZ
#define PBKDF2_SALT_SZ 8
#endif 

#ifndef PBKDF2_ITER
#define PBKDF2_ITER 4000
#endif

void sqlite3pager_get_codec(Pager *pPager, void **ctx);
int sqlite3pager_is_mj_pgno(Pager *pPager, Pgno pgno);

#endif
#endif
/* END CRYPTO */
