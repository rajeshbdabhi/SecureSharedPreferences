package com.securesharedpreferences

import android.content.Context
import android.content.SharedPreferences
import android.os.AsyncTask
import java.text.ParseException

/**
 * Created on 30-09-2019.
 */
class SecureOldSharedPreferences(
    context: Context,
    val oldPref: SharedPreferences,
    oldPrefName: String,
    newPassword: String,
    val encryptListener: EncryptListener?
) :
    AsyncTask<String, Int, String>() {

    //initialise
    val secureSharedPreferences = SecureSharedPreferences(context, oldPrefName, newPassword)
    // shared preference editor
    val editor = secureSharedPreferences.edit()

    override fun onPreExecute() {
        super.onPreExecute()
    }

    override fun doInBackground(vararg p0: String?): String {
        for (oldData in oldPref.all) {
            try {
                if (!oldData.key.isNullOrEmpty()) {
                    if (oldData.value is String) {
                        editor.putString(oldData.key, oldData.value.toString())
                    } else if (oldData.value != null && oldData.value.toString().isNotEmpty() && oldData.value is Int) {
                        editor.putInt(oldData.key, oldData.value.toString().toInt())
                    } else if (oldData.value != null && oldData.value.toString().isNotEmpty() && oldData.value is Boolean) {
                        editor.putBoolean(oldData.key, oldData.value.toString().toBoolean())
                    } else if (oldData.value != null && oldData.value.toString().isNotEmpty() && oldData.value is Float) {
                        editor.putFloat(oldData.key, oldData.value.toString().toFloat())
                    } else if (oldData.value != null && oldData.value.toString().isNotEmpty() && oldData.value is Long) {
                        editor.putLong(oldData.key, oldData.value.toString().toLong())
                    }
                }
            } catch (e: ParseException) {
                e.printStackTrace()
            }
        }
        return "Done"
    }

    override fun onPostExecute(result: String?) {
        super.onPostExecute(result)
        if (encryptListener != null) {
            encryptListener.encrypted()
        }
    }

    public interface EncryptListener {
        fun encrypted()
    }

}