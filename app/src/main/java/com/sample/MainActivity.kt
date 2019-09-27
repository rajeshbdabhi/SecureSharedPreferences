package com.sample

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
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

    }
}
