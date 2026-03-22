/**
 * TOTP - Time-based One-Time Password
 * RFC 6238 implementation
 */

#include "totp_auth.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Get current time step */
static time_t get_time_step(time_t timestamp, int period) {
    return timestamp / period;
}

/* Convert time step to counter value */
static uint64_t time_step_to_counter(time_t time_step) {
    return (uint64_t)time_step;
}

/* Dynamic truncation per RFC 4226 */
static uint32_t dynamic_truncate(const uint8_t *hash, int hash_len) {
    (void)hash_len;
    int offset = hash[hash_len - 1] & 0x0F;
    uint32_t truncated = 0;
    
    for (int i = 0; i < 4; i++) {
        truncated = (truncated << 8) | hash[offset + i];
    }
    
    truncated &= 0x7FFFFFFF;
    return truncated;
}

/* Dynamic truncation - extracts bytes from hash */
static uint32_t dynamic_truncate_raw(const uint8_t *hash) {
    int offset = hash[hash[19] & 0x0F];
    uint32_t truncated = 0;
    
    for (int i = 0; i < 4; i++) {
        truncated = (truncated << 8) | hash[offset + i];
    }
    
    return truncated & 0x7FFFFFFF;
}

/* Calculate HMAC based on algorithm */
static void calc_hmac(const uint8_t *key, int key_len,
                      const uint8_t *data, int data_len,
                      uint8_t *output, int algorithm) {
    switch (algorithm) {
        case ALGO_SHA256:
            HMAC(EVP_sha256(), key, key_len, data, data_len, output, NULL);
            break;
        case ALGO_SHA512:
            HMAC(EVP_sha512(), key, key_len, data, data_len, output, NULL);
            break;
        case ALGO_SHA1:
        default:
            HMAC(EVP_sha1(), key, key_len, data, data_len, output, NULL);
            break;
    }
}

/* Get hash length for algorithm */
static int get_hash_len(int algorithm) {
    switch (algorithm) {
        case ALGO_SHA256:
            return SHA256_DIGEST_LENGTH;
        case ALGO_SHA512:
            return SHA512_DIGEST_LENGTH;
        case ALGO_SHA1:
        default:
            return 20; /* SHA1_DIGEST_LENGTH is 20 */
    }
}

TOTPResult totp_generate(const char *secret, int period, int digits,
                          int algorithm, time_t timestamp) {
    TOTPResult result = {{0}, 0};
    
    if (!secret || strlen(secret) == 0) {
        return result;
    }
    
    if (timestamp == 0) {
        timestamp = time(NULL);
    }
    
    time_t time_step = get_time_step(timestamp, period);
    result.remaining = (int)(period - (timestamp % period));
    
    /* Decode secret from base32 */
    uint8_t key[128];
    int key_len = base32_decode(secret, key);
    if (key_len <= 0) {
        return result;
    }
    
    /* Convert counter to big-endian */
    uint64_t counter = time_step_to_counter(time_step);
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }
    
    /* Calculate HMAC */
    uint8_t hash[SHA512_DIGEST_LENGTH];
    int hash_len = get_hash_len(algorithm);
    calc_hmac(key, key_len, counter_bytes, 8, hash, algorithm);
    
    /* Dynamic truncation */
    uint32_t truncated = dynamic_truncate_raw(hash);
    
    /* Generate code */
    uint32_t divisor = (uint32_t)pow(10.0, (double)digits);
    uint32_t code = truncated % divisor;
    
    snprintf(result.code, sizeof(result.code), "%0*d", digits, code);
    
    return result;
}

int totp_verify(const char *secret, const char *code,
                 int period, int digits, int algorithm, int window) {
    time_t now = time(NULL);
    
    for (int i = -window; i <= window; i++) {
        time_t timestamp = now + (i * (time_t)period);
        TOTPResult result = totp_generate(secret, period, digits, algorithm, timestamp);
        
        if (strcmp(result.code, code) == 0) {
            return 1;
        }
    }
    
    return 0;
}
