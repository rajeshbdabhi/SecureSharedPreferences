package com.securesharedpreferences

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log

import java.io.UnsupportedEncodingException
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import java.nio.file.Files.size


class SecureSharedPreferences(
    context: Context,
    prefName: String,
    private val ENCRYPTED_PASSWORD: String
) : SharedPreferences {

    internal var sharedPreferences: SharedPreferences

    init {
        sharedPreferences = context.getSharedPreferences(prefName, Context.MODE_PRIVATE)
    }

    override fun getAll(): Map<String, *>? {
        val encryptedMap = sharedPreferences.all
        val decryptedMap = HashMap<String, Any>(encryptedMap.size)

        for ((key, cipherText) in encryptedMap) {
            try {
                val stringSet = getDecryptedStringSet(cipherText)

                if (stringSet != null) {
                    decryptedMap[key] = stringSet
                } else {
                    decryptedMap[key] = decrypt(ENCRYPTED_PASSWORD, cipherText.toString())
                }
            } catch (e: Exception) {
                if (DEBUG_LOG_ENABLED) {
                    Log.w(TAG, "error during getAll", e)
                }
                // Ignore issues that unencrypted values and use instead raw cipher text string
                decryptedMap[key] = cipherText.toString()
            }
        }
        return decryptedMap
    }

    override fun getString(s: String, s1: String?): String? {
        try {
            return decrypt(ENCRYPTED_PASSWORD, sharedPreferences.getString(s, s1))
        } catch (e: ClassCastException) {
            return s1
        }
    }

    override fun getStringSet(s: String, set: Set<String>?): Set<String>? {
        try {
            val encryptSet = sharedPreferences.getStringSet(s, set)
            val decriptedSet = HashSet<String>(encryptSet!!.size)
            for (value in encryptSet) {
                val descriptData = decrypt(ENCRYPTED_PASSWORD, value)
                decriptedSet.add(descriptData)
            }
            return decriptedSet
        } catch (e: Exception) {
            return set
        }
    }

    override fun getInt(s: String, i: Int): Int {
        try {
            return Integer.parseInt(
                decrypt(
                    ENCRYPTED_PASSWORD,
                    sharedPreferences.getString(s, null)
                )
            )
        } catch (e: Exception) {
            return i
        }
    }

    override fun getLong(s: String, l: Long): Long {
        try {
            return java.lang.Long.parseLong(
                decrypt(
                    ENCRYPTED_PASSWORD,
                    sharedPreferences.getString(s, null)
                )
            )
        } catch (e: Exception) {
            return l
        }
    }

    override fun getFloat(s: String, v: Float): Float {
        try {
            return java.lang.Float.parseFloat(
                decrypt(
                    ENCRYPTED_PASSWORD,
                    sharedPreferences.getString(s, null)
                )
            )
        } catch (e: Exception) {
            return v
        }
    }

    override fun getBoolean(s: String, b: Boolean): Boolean {
        try {
            return java.lang.Boolean.parseBoolean(
                decrypt(
                    ENCRYPTED_PASSWORD,
                    sharedPreferences.getString(s, null)
                )
            )
        } catch (e: Exception) {
            return b
        }
    }

    override fun contains(s: String): Boolean {
        return false
    }

    override fun edit(): Editor {
        return Editor()
    }

    override fun registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener: SharedPreferences.OnSharedPreferenceChangeListener) {

    }

    override fun unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener: SharedPreferences.OnSharedPreferenceChangeListener) {

    }

    inner class Editor internal constructor() : SharedPreferences.Editor {

        internal var editor: SharedPreferences.Editor

        init {
            editor = sharedPreferences.edit()
        }

        override fun putString(s: String, s1: String?): SharedPreferences.Editor {
            val encryptedData = encrypt(ENCRYPTED_PASSWORD, s1)
            editor.putString(s, encryptedData).apply()
            return this
        }

        override fun putStringSet(s: String, set: Set<String>?): SharedPreferences.Editor {
            val encryptSet = HashSet<String>(set!!.size)
            for (value in set) {
                val encryptedData = encrypt(ENCRYPTED_PASSWORD, value)
                encryptSet.add(encryptedData)
            }
            editor.putStringSet(s, encryptSet)
            return this
        }

        override fun putInt(s: String, i: Int): SharedPreferences.Editor {
            val encryptedData = encrypt(ENCRYPTED_PASSWORD, Integer.toString(i))
            editor.putString(s, encryptedData).apply()
            return this
        }

        override fun putLong(s: String, l: Long): SharedPreferences.Editor {
            val encryptedData = encrypt(ENCRYPTED_PASSWORD, java.lang.Long.toString(l))
            editor.putString(s, encryptedData).apply()
            return this
        }

        override fun putFloat(s: String, v: Float): SharedPreferences.Editor {
            val encryptedData = encrypt(ENCRYPTED_PASSWORD, java.lang.Float.toString(v))
            editor.putString(s, encryptedData).apply()
            return this
        }

        override fun putBoolean(s: String, b: Boolean): SharedPreferences.Editor {
            val encryptedData = encrypt(ENCRYPTED_PASSWORD, java.lang.Boolean.toString(b))
            editor.putString(s, encryptedData).apply()
            return this
        }

        override fun remove(s: String): SharedPreferences.Editor {
            editor.remove(s)
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            editor.clear()
            return this
        }

        override fun commit(): Boolean {
            return editor.commit()
        }

        override fun apply() {
            editor.apply()
        }
    }

    companion object {

        private val TAG = "SecureSharedPreferences"

        //SecureSharedPreferences-ObjC uses CBC and PKCS7Padding
        private val AES_MODE = "AES/CBC/PKCS7Padding"
        private val CHARSET = "UTF-8"

        //SecureSharedPreferences-ObjC uses SHA-256 (and so a 256-bit key)
        private val HASH_ALGORITHM = "SHA-256"

        //SecureSharedPreferences-ObjC uses blank IV (not the best security, but the aim here is compatibility)
        private val ivBytes = byteArrayOf(
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00
        )

        //togglable log option (please turn off in live!)
        var DEBUG_LOG_ENABLED = false

        /**
         * Generates SHA256 hash of the password which is used as key
         *
         * @param password used to generated key
         * @return SHA256 of the password
         */
        @Throws(NoSuchAlgorithmException::class, UnsupportedEncodingException::class)
        private fun generateKey(password: String): SecretKeySpec {
            val digest = MessageDigest.getInstance(HASH_ALGORITHM)
            val bytes = password.toByteArray(charset("UTF-8"))
            digest.update(bytes, 0, bytes.size)
            val key = digest.digest()

            log("SHA-256 key ", key)

            return SecretKeySpec(key, "AES")
        }


        /**
         * Encrypt and encode message using 256-bit AES with key generated from password.
         *
         * @param password used to generated key
         * @param message  the thing you want to encrypt assumed String UTF-8
         * @return Base64 encoded CipherText
         * @throws GeneralSecurityException if problems occur during encryption
         */
        fun encrypt(password: String, message: String?): String {

            try {
                val key = generateKey(password)

                log("message", message)

                val cipherText = encrypt(key, ivBytes, message!!.toByteArray(charset(CHARSET)))

                //NO_WRAP is important as was getting \n at the end
                val encoded = Base64.encodeToString(cipherText, Base64.NO_WRAP)
                log("Base64.NO_WRAP", encoded)
                return encoded
            } catch (e: UnsupportedEncodingException) {
                if (DEBUG_LOG_ENABLED)
                    Log.e(TAG, "UnsupportedEncodingException ", e)
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            } catch (e: GeneralSecurityException) {
                e.printStackTrace()
            }

            return ""
        }


        /**
         * More flexible AES encrypt that doesn't encode
         *
         * @param key     AES key typically 128, 192 or 256 bit
         * @param iv      Initiation Vector
         * @param message in bytes (assumed it's already been decoded)
         * @return Encrypted cipher text (not encoded)
         * @throws GeneralSecurityException if something goes wrong during encryption
         */
        @Throws(GeneralSecurityException::class)
        fun encrypt(key: SecretKeySpec, iv: ByteArray, message: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(AES_MODE)
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
            val cipherText = cipher.doFinal(message)
            log("cipherText", cipherText)
            return cipherText
        }


        /**
         * Decrypt and decode ciphertext using 256-bit AES with key generated from password
         *
         * @param password                used to generated key
         * @param base64EncodedCipherText the encrpyted message encoded with base64
         * @return message in Plain text (String UTF-8)
         * @throws GeneralSecurityException if there's an issue decrypting
         */
        fun decrypt(password: String, base64EncodedCipherText: String?): String {
            try {
                val key = generateKey(password)

                log("base64EncodedCipherText", base64EncodedCipherText)
                val decodedCipherText = Base64.decode(base64EncodedCipherText, Base64.NO_WRAP)
                log("decodedCipherText", decodedCipherText)

                val decryptedBytes = decrypt(key, ivBytes, decodedCipherText)

                log("decryptedBytes", decryptedBytes)
                val message = String(decryptedBytes, charset(CHARSET))
                log("message", message)

                return message
            } catch (e: Exception) {
                if (DEBUG_LOG_ENABLED)
                    Log.e(TAG, "UnsupportedEncodingException $e")

                //throw new GeneralSecurityException(e);
                return ""
            }

        }


        /**
         * More flexible AES decrypt that doesn't encode
         *
         * @param key               AES key typically 128, 192 or 256 bit
         * @param iv                Initiation Vector
         * @param decodedCipherText in bytes (assumed it's already been decoded)
         * @return Decrypted message cipher text (not encoded)
         * @throws GeneralSecurityException if something goes wrong during encryption
         */
        @Throws(GeneralSecurityException::class)
        fun decrypt(key: SecretKeySpec, iv: ByteArray, decodedCipherText: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(AES_MODE)
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
            val decryptedBytes = cipher.doFinal(decodedCipherText)

            log("decryptedBytes", decryptedBytes)

            return decryptedBytes
        }


        private fun log(what: String, bytes: ByteArray) {
            if (DEBUG_LOG_ENABLED)
                Log.d(TAG, what + "[" + bytes.size + "] [" + bytesToHex(bytes) + "]")
        }

        private fun log(what: String, value: String?) {
            if (DEBUG_LOG_ENABLED)
                Log.d(TAG, what + "[" + value!!.length + "] [" + value + "]")
        }


        /**
         * Converts byte array to hexidecimal useful for logging and fault finding
         *
         * @param bytes
         * @return
         */
        private fun bytesToHex(bytes: ByteArray): String {
            val hexArray = charArrayOf(
                '0',
                '1',
                '2',
                '3',
                '4',
                '5',
                '6',
                '7',
                '8',
                '9',
                'A',
                'B',
                'C',
                'D',
                'E',
                'F'
            )
            val hexChars = CharArray(bytes.size * 2)
            var v: Int
            for (j in bytes.indices) {
                v = bytes[j].toInt() and 0xFF
                hexChars[j * 2] = hexArray[v.ushr(4)]
                hexChars[j * 2 + 1] = hexArray[v and 0x0F]
            }
            return String(hexChars)
        }
    }

    private fun getDecryptedStringSet(cipherText: Any?): Set<String>? {
        if (cipherText == null) {
            return null
        }

        val isSet = cipherText is Set<*>

        if (!isSet) {
            return null
        }

        val encryptedSet = cipherText as Set<*>?
        val decryptedSet = java.util.HashSet<String>()

        for (`object` in encryptedSet!!) {
            if (`object` is String) {
                decryptedSet.add(decrypt(ENCRYPTED_PASSWORD, `object`))
            } else {
                return null
            }
        }
        return decryptedSet
    }

}
