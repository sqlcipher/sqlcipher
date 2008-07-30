/* 
** crypto.h developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
**
*/
/* BEGIN CRYPTO */
#ifndef CRYPTO_H
#define CRYPTO_H

#define CIPHER EVP_aes_256_cfb()
#define DIGEST EVP_sha1()

/* HDR_SIZE allocates 16 bytes for random salt and 8 bytes for page size */
#define HDR_SZ 24

#endif
/* END CRYPTO */