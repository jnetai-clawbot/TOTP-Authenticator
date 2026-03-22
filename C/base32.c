/**
 * Base32 encoding/decoding
 */

#include "totp_auth.h"
#include <ctype.h>
#include <string.h>

/* Base32 encoding table */
static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_encode(const uint8_t *data, int len, char *output) {
    int i;
    int output_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    for (i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        
        while (bits_left >= 5) {
            output[output_len++] = base32_chars[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }
    
    if (bits_left > 0) {
        output[output_len++] = base32_chars[(buffer << (5 - bits_left)) & 0x1F];
    }
    
    output[output_len] = '\0';
    return output_len;
}

int base32_decode(const char *input, uint8_t *output) {
    int len = strlen(input);
    int i;
    int output_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    /* Remove padding and convert to uppercase */
    for (i = 0; i < len; i++) {
        char c = toupper(input[i]);
        if (c == '=') continue;
        
        const char *pos = strchr(base32_chars, c);
        if (!pos) continue;
        
        buffer = (buffer << 5) | (pos - base32_chars);
        bits_left += 5;
        
        while (bits_left >= 8) {
            output[output_len++] = (buffer >> (bits_left - 8)) & 0xFF;
            bits_left -= 8;
        }
    }
    
    return output_len;
}
