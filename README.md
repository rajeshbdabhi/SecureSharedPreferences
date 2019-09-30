# SecureSharedPreferences
SecureSharedPreferences
[![](https://jitpack.io/v/rajeshbdabhi/SecureSharedPreferences.svg)](https://jitpack.io/#rajeshbdabhi/SecureSharedPreferences)

This library provice to save and get data same as SharedPreferences with perform AES encryption.

Step 1. Add the JitPack repository to your build file

Add it in your root build.gradle at the end of repositories
	
	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}


Step 2. Add the dependency

Add it in your app level build.gradle

	dependencies {
    		implementation 'com.github.rajeshbdabhi:SecureSharedPreferences:latest-version'
	}
	
Usage:

SecureSharedPreferences use like normal SharedPreferences

	//initialise
	val secureSharedPreferences = SecureSharedPreferences(this, "pref_name", "password")	
        
	// shared preference editor
	val editor = secureSharedPreferences.edit()
        
	// put string
	editor.putString("key", "value")
	
	//get string
	val key = secureSharedPreferences.getString("key", "this default value")
	
Version 1.0.1
Secure old SharedPreference:

	val oldPref = getSharedPreferences("old_name", 0)
        SecureOldSharedPreferences(
            this,
            oldPref,
            "old_name",
            "1234",
            object : SecureOldSharedPreferences.EncryptListener {
                override fun encrypted() {
                    // encryption done
                }
            }).execute()
	    
	// featch new SecureSharedPreferences with old name and new password like this.
	val newsecureSharedPreferences = SecureSharedPreferences(this@MainActivity, "old_name", "1234")


Encrypt and Decrypt other strings:

	// for simple encrypt and decrypt any string data
	val encoded = SecureSharedPreferences.encrypt("test", "title")
	val decod = SecureSharedPreferences.decrypt("test", encoded)
	
