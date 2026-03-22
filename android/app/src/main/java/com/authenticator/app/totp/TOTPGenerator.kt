package com.authenticator.app.totp

import android.util.Base64
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

class TOTPGenerator {
    
    fun generate(secret: String, period: Int = 30, digits: Int = 6, algorithm: String = "SHA1"): String {
        val timestamp = System.currentTimeMillis() / 1000
        return generateTOTP(secret, timestamp, period, digits, algorithm)
    }
    
    fun getTimeRemaining(period: Int = 30): Int {
        val timestamp = System.currentTimeMillis() / 1000
        return period - (timestamp % period).toInt()
    }
    
    fun verify(secret: String, code: String, period: Int = 30, digits: Int = 6, window: Int = 1): Boolean {
        val timestamp = System.currentTimeMillis() / 1000
        
        for (offset in -window..window) {
            val testTime = timestamp + (offset * period)
            val testCode = generateTOTP(secret, testTime, period, digits, "SHA1")
            if (testCode == code) return true
        }
        return false
    }
    
    private fun generateTOTP(secret: String, timestamp: Long, period: Int, digits: Int, algorithm: String): String {
        val key = base32Decode(secret)
        val counter = timestamp / period
        
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        
        val hmacAlgorithm = when (algorithm.uppercase()) {
            "SHA256" -> "HmacSHA256"
            "SHA512" -> "HmacSHA512"
            else -> "HmacSHA1"
        }
        
        val mac = Mac.getInstance(hmacAlgorithm)
        mac.init(SecretKeySpec(key, hmacAlgorithm))
        val hash = mac.doFinal(counterBytes)
        
        val offset = hash[hash.size - 1].toInt() and 0x0F
        
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)
        
        val otp = binary % 10.0.pow(digits.toDouble()).toInt()
        
        return otp.toString().padStart(digits, '0')
    }
    
    private fun base32Decode(input: String): ByteArray {
        val base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val cleanedInput = input.uppercase().replace(" ", "").replace("=", "")
        
        val result = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0
        
        for (char in cleanedInput) {
            val value = base32Chars.indexOf(char)
            if (value < 0) continue
            
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            
            if (bitsLeft >= 8) {
                result.add(((buffer shr (bitsLeft - 8)) and 0xFF).toByte())
                bitsLeft -= 8
            }
        }
        
        return result.toByteArray()
    }
    
    fun generateSecret(): String {
        val bytes = ByteArray(20)
        java.security.SecureRandom().nextBytes(bytes)
        return base32Encode(bytes)
    }
    
    private fun base32Encode(data: ByteArray): String {
        val base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val result = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            
            while (bitsLeft >= 5) {
                result.append(base32Chars[(buffer shr (bitsLeft - 5)) and 0x1F])
                bitsLeft -= 5
            }
        }
        
        if (bitsLeft > 0) {
            result.append(base32Chars[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        
        return result.toString()
    }
}
