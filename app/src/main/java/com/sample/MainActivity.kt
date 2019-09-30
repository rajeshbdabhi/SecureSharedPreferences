package com.sample

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.securesharedpreferences.SecureOldSharedPreferences
import com.securesharedpreferences.SecureSharedPreferences

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        //initialise
        val secureSharedPreferences = SecureSharedPreferences(this, "pref_name", "1234")
        // shared preference editor
        val editor = secureSharedPreferences.edit()

        // put string
        editor.putString("key", "value")
        //get string
        val key = secureSharedPreferences.getString("key", "this default value")


        // for simple encode and decode any string data
        val encoded = SecureSharedPreferences.encrypt("test", "title")
        val decod = SecureSharedPreferences.decrypt("test", encoded)

        //secure old pref
        val oldPref = getSharedPreferences("old_name", 0)
        SecureOldSharedPreferences(
            this,
            oldPref,
            "old_name",
            "1234",
            object : SecureOldSharedPreferences.EncryptListener {
                override fun encrypted() {
                    // encryption done
                    val newsecureSharedPreferences =
                        SecureSharedPreferences(this@MainActivity, "old_name", "1234")
                }
            }).execute()

    }

}
