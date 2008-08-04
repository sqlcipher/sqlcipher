/* 
** SQLite Cipher
** crypto.h developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** July 30, 2008
**
** This code is released under the same public domain terms as SQLite itself.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**  
*/
/* BEGIN CRYPTO */
#ifndef CRYPTO_H
#define CRYPTO_H

#define CIPHER EVP_aes_256_cfb()
#define DIGEST EVP_sha256()
#define CIPHER_DECRYPT 0
#define CIPHER_ENCRYPT 1

/* HDR_SIZE allocates 16 bytes for random salt and 8 bytes for page size */
#define HDR_SZ 24

#endif
/* END CRYPTO */
