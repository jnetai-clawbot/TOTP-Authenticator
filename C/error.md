jay@jnetai:~/Documents/Scripts/AI/openclaw/job16$ cd C
make
gcc -Wall -Wextra -O2 -std=c11 -o totp_auth totp_auth.c -lcrypto -lsqlite3
totp_auth.c: In function ‘base32_encode’:
totp_auth.c:69:12: warning: unused variable ‘j’ [-Wunused-variable]
   69 |     int i, j;
      |            ^
totp_auth.c: In function ‘totp_generate’:
totp_auth.c:221:43: warning: implicit declaration of function ‘pow’ [-Wimplicit-function-declaration]
  221 |     uint32_t code = truncated % (uint32_t)pow(10, digits);
      |                                           ^~~
totp_auth.c:132:1: note: include ‘<math.h>’ or provide a declaration of ‘pow’
  131 | #include <openssl/hmac.h>
  +++ |+#include <math.h>
  132 | #include <openssl/evp.h>
totp_auth.c:221:43: warning: incompatible implicit declaration of built-in function ‘pow’ [-Wbuiltin-declaration-mismatch]
  221 |     uint32_t code = truncated % (uint32_t)pow(10, digits);
      |                                           ^~~
totp_auth.c:221:43: note: include ‘<math.h>’ or provide a declaration of ‘pow’
totp_auth.c: In function ‘init_callback’:
totp_auth.c:300:32: warning: unused parameter ‘context’ [-Wunused-parameter]
  300 | static int init_callback(void *context, int argc, char **argv, char **col_names) {
      |                          ~~~~~~^~~~~~~
totp_auth.c:300:45: warning: unused parameter ‘argc’ [-Wunused-parameter]
  300 | static int init_callback(void *context, int argc, char **argv, char **col_names) {
      |                                         ~~~~^~~~
totp_auth.c:300:58: warning: unused parameter ‘argv’ [-Wunused-parameter]
  300 | static int init_callback(void *context, int argc, char **argv, char **col_names) {
      |                                                   ~~~~~~~^~~~
totp_auth.c:300:71: warning: unused parameter ‘col_names’ [-Wunused-parameter]
  300 | static int init_callback(void *context, int argc, char **argv, char **col_names) {
      |                                                                ~~~~~~~^~~~~~~~~
totp_auth.c: In function ‘storage_add_site’:
totp_auth.c:348:11: warning: unused variable ‘err_msg’ [-Wunused-variable]
  348 |     char *err_msg = NULL;
      |           ^~~~~~~
totp_auth.c: In function ‘main’:
totp_auth.c:849:9: warning: ignoring return value of ‘scanf’ declared with attribute ‘warn_unused_result’ [-Wunused-result]
  849 |         scanf(" %c", &confirm);
      |         ^~~~~~~~~~~~~~~~~~~~~~
totp_auth.c: At top level:
totp_auth.c:559:12: warning: ‘decrypt_aes_256_gcm’ defined but not used [-Wunused-function]
  559 | static int decrypt_aes_256_gcm(const unsigned char *input, int input_len,
      |            ^~~~~~~~~~~~~~~~~~~
totp_auth.c:491:12: warning: ‘encrypt_aes_256_gcm’ defined but not used [-Wunused-function]
  491 | static int encrypt_aes_256_gcm(const char *plaintext, const char *password,
      |            ^~~~~~~~~~~~~~~~~~~
totp_auth.c:68:12: warning: ‘base32_encode’ defined but not used [-Wunused-function]
   68 | static int base32_encode(const uint8_t *data, int len, char *output) {
      |            ^~~~~~~~~~~~~
/usr/bin/ld: /tmp/cc9rEiaL.o: undefined reference to symbol 'pow@@GLIBC_2.29'
/usr/bin/ld: /lib/aarch64-linux-gnu/libm.so.6: error adding symbols: DSO missing from command line
collect2: error: ld returned 1 exit status
make: *** [Makefile:20: totp_auth] Error 1

