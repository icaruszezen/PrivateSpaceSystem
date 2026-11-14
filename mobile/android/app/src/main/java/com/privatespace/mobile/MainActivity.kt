package com.privatespace.mobile

import android.content.Context
import android.os.Bundle
import android.view.WindowManager
import com.getcapacitor.BridgeActivity

class MainActivity : BridgeActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        // Register hardware security & Android integration plugin prior to Bridge initialization
        registerPlugin(PrivateSpaceNativePlugin::class.java)

        // Enforce FLAG_SECURE prior to first frame draw unless explicitly disabled by user
        val prefs = getSharedPreferences(
            PrivateSpaceNativePlugin.PREFS_NAME,
            Context.MODE_PRIVATE,
        )
        val shieldEnabled = prefs.getBoolean(
            PrivateSpaceNativePlugin.PREF_FLAG_SECURE,
            true,
        )
        if (shieldEnabled) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }

        super.onCreate(savedInstanceState)
    }
}
