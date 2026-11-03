package com.reach.unlock

import android.app.Activity
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.DeviceFilter
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.util.Callback
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.client.WebAuthnClient
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.yubikit.fido.webauthn.SerializationType
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class SealArgs {
    lateinit var alias: String
    lateinit var secret: String
    var title: String = "Reach"
    var subtitle: String? = null
    var cancel: String = "Cancel"
}

@InvokeArg
class OpenArgs {
    lateinit var alias: String
    lateinit var iv: String
    lateinit var ciphertext: String
    var title: String = "Reach"
    var subtitle: String? = null
    var cancel: String = "Cancel"
}

@InvokeArg
class AliasArgs {
    lateinit var alias: String
}

@InvokeArg
class MakeCredentialArgs {
    lateinit var rpId: String
    lateinit var userId: String
    lateinit var label: String
    var pin: String? = null
    var exclude: Array<String> = arrayOf()
}

@InvokeArg
class UriArgs {
    lateinit var uri: String
    var data: String? = null
}

@InvokeArg
class HmacSecretArgs {
    lateinit var rpId: String
    var credentialIds: Array<String> = arrayOf()
    lateinit var salt: String
    var pin: String? = null
}

/**
 * The Android side of Reach's vault unlock. Reach's Rust code calls these;
 * the webview never does. Byte strings travel as standard base64.
 *
 * - The fingerprint: an AES-256-GCM key in the Android Keystore that needs a
 *   strong biometric check for every use, and is invalidated when a new
 *   fingerprint is enrolled, seals the vault key. BiometricPrompt releases the
 *   cipher only after the check ("Include a cryptographic solution",
 *   developer.android.com/identity/sign-in/biometric-auth).
 * - Security keys: a FIDO2 key's hmac-secret, through the WebAuthn PRF
 *   extension of Yubico's yubikit-android, over USB or NFC, for any FIDO2
 *   key and not only Yubico's.
 */
@TauriPlugin
class UnlockPlugin(private val activity: Activity) : Plugin(activity) {
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    // ----- Fingerprint -----------------------------------------------------

    @Command
    fun biometricStatus(invoke: Invoke) {
        val available = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
        invoke.resolve(JSObject().apply { put("available", available) })
    }

    @Command
    fun biometricSeal(invoke: Invoke) {
        val args = invoke.parseArgs(SealArgs::class.java)
        try {
            deleteKey(args.alias)
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, newKey(args.alias))
            prompt(invoke, args.title, args.subtitle, args.cancel, cipher) { released ->
                val sealed = released.doFinal(decode(args.secret))
                JSObject().apply {
                    put("iv", encode(released.iv))
                    put("ciphertext", encode(sealed))
                }
            }
        } catch (e: Exception) {
            invoke.reject(e.message ?: "The fingerprint key could not be made")
        }
    }

    @Command
    fun biometricOpen(invoke: Invoke) {
        val args = invoke.parseArgs(OpenArgs::class.java)
        val key = keyStore().getKey(args.alias, null) as? SecretKey
        if (key == null) {
            invoke.reject("The fingerprint key is gone; use your master password", INVALIDATED)
            return
        }
        val cipher = Cipher.getInstance(AES_GCM)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, decode(args.iv)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            // A fingerprint was added or removed since: the key is void, by
            // design. The master password still opens the vault.
            deleteKey(args.alias)
            invoke.reject("Your fingerprints changed; use your master password, then turn this on again", INVALIDATED)
            return
        } catch (e: Exception) {
            invoke.reject(e.message ?: "The fingerprint key could not be used")
            return
        }
        prompt(invoke, args.title, args.subtitle, args.cancel, cipher) { released ->
            JSObject().apply { put("secret", encode(released.doFinal(decode(args.ciphertext)))) }
        }
    }

    @Command
    fun biometricForget(invoke: Invoke) {
        val args = invoke.parseArgs(AliasArgs::class.java)
        deleteKey(args.alias)
        invoke.resolve()
    }

    private fun prompt(
        invoke: Invoke,
        title: String,
        subtitle: String?,
        cancel: String,
        cipher: Cipher,
        use: (Cipher) -> JSObject,
    ) {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val released = result.cryptoObject?.cipher
                if (released == null) {
                    invoke.reject("The fingerprint check released no key")
                    return
                }
                try {
                    invoke.resolve(use(released))
                } catch (e: Exception) {
                    invoke.reject(e.message ?: "The fingerprint key could not be used")
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                invoke.reject(errString.toString(), errorCode.toString())
            }
            // onAuthenticationFailed is a finger that did not match; the
            // prompt stays up for another try, so there is nothing to do.
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .apply { subtitle?.let { setSubtitle(it) } }
            .setNegativeButtonText(cancel)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()
        BiometricPrompt(activity as FragmentActivity, ContextCompat.getMainExecutor(activity), callback)
            .authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun newKey(alias: String): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Every use needs its own check, by a strong biometric only.
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(spec.build())
        return generator.generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun deleteKey(alias: String) {
        try {
            keyStore().deleteEntry(alias)
        } catch (_: Exception) {
            // Nothing there to delete.
        }
    }

    // ----- Keychain ----------------------------------------------------------
    //
    // Android's answer to the desktop keychain: the vault key, sealed by an
    // AES-256-GCM key that lives in the Android Keystore and never leaves it.
    // No user check here (that is the fingerprint's job, above): this is what
    // lets Reach open by itself after a restart, as it does on a desktop.

    @Command
    fun keystoreSeal(invoke: Invoke) {
        val args = invoke.parseArgs(SealArgs::class.java)
        try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, deviceKey(args.alias))
            val sealed = cipher.doFinal(decode(args.secret))
            invoke.resolve(JSObject().apply {
                put("iv", encode(cipher.iv))
                put("ciphertext", encode(sealed))
            })
        } catch (e: Exception) {
            invoke.reject(e.message ?: "The Android Keystore could not seal the key")
        }
    }

    @Command
    fun keystoreOpen(invoke: Invoke) {
        val args = invoke.parseArgs(OpenArgs::class.java)
        try {
            val key = keyStore().getKey(args.alias, null) as? SecretKey
            if (key == null) {
                invoke.reject("The Android Keystore has no key for Reach", MISSING)
                return
            }
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, decode(args.iv)))
            invoke.resolve(JSObject().apply { put("secret", encode(cipher.doFinal(decode(args.ciphertext)))) })
        } catch (e: Exception) {
            invoke.reject(e.message ?: "The Android Keystore could not open the key")
        }
    }

    @Command
    fun keystoreForget(invoke: Invoke) {
        val args = invoke.parseArgs(AliasArgs::class.java)
        deleteKey(args.alias)
        invoke.resolve()
    }

    /** The Keystore key under `alias`, made on first use. */
    private fun deviceKey(alias: String): SecretKey {
        (keyStore().getKey(alias, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }

    // ----- Files the user picked ------------------------------------------

    /** Read a `content://` link the system's file picker handed back. */
    @Command
    fun readUri(invoke: Invoke) {
        val args = invoke.parseArgs(UriArgs::class.java)
        io.execute {
            try {
                val bytes = activity.contentResolver.openInputStream(Uri.parse(args.uri))?.use { it.readBytes() }
                    ?: throw IllegalStateException("The file could not be opened")
                invoke.resolve(JSObject().apply { put("data", encode(bytes)) })
            } catch (e: Exception) {
                invoke.reject(e.message ?: "The file could not be read")
            }
        }
    }

    /** Write a `content://` link the system's save dialog handed back. */
    @Command
    fun writeUri(invoke: Invoke) {
        val args = invoke.parseArgs(UriArgs::class.java)
        io.execute {
            try {
                // "wt": truncate, so a shorter file never keeps a longer one's tail.
                activity.contentResolver.openOutputStream(Uri.parse(args.uri), "wt")?.use {
                    it.write(decode(args.data ?: ""))
                } ?: throw IllegalStateException("The file could not be opened for writing")
                invoke.resolve()
            } catch (e: Exception) {
                invoke.reject(e.message ?: "The file could not be written")
            }
        }
    }

    // ----- Security keys ---------------------------------------------------

    @Command
    fun keyMakeCredential(invoke: Invoke) {
        val args = invoke.parseArgs(MakeCredentialArgs::class.java)
        withSecurityKey(invoke) { device ->
            WebAuthnClient.create(device, null).use { client ->
                val options = PublicKeyCredentialCreationOptions.fromMap(
                    mapOf(
                        "rp" to mapOf("id" to args.rpId, "name" to "Reach"),
                        "user" to mapOf(
                            "id" to urlEncode(decode(args.userId)),
                            "name" to args.label,
                            "displayName" to args.label,
                        ),
                        "challenge" to urlEncode(random(32)),
                        "pubKeyCredParams" to listOf(mapOf("type" to "public-key", "alg" to -7)),
                        "excludeCredentials" to args.exclude.map {
                            mapOf("type" to "public-key", "id" to urlEncode(decode(it)))
                        },
                        // Non-resident, as systemd-cryptenroll makes them: the
                        // key's limited storage stays free.
                        "authenticatorSelection" to mapOf(
                            "residentKey" to "discouraged",
                            "userVerification" to "required",
                        ),
                        "attestation" to "none",
                        "extensions" to mapOf("prf" to emptyMap<String, Any>()),
                    ),
                )
                val credential = client.makeCredential(
                    ClientDataProvider.fromHash(random(32)),
                    options,
                    args.rpId,
                    args.pin?.toCharArray(),
                    null,
                    null,
                )
                val prf = credential.clientExtensionResults?.toMap(SerializationType.JSON)?.get("prf") as? Map<*, *>
                if (prf?.get("enabled") != true) {
                    throw IllegalStateException("This security key does not support what unlocking needs (hmac-secret)")
                }
                JSObject().apply { put("credentialId", encode(credential.rawId)) }
            }
        }
    }

    @Command
    fun keyHmacSecret(invoke: Invoke) {
        val args = invoke.parseArgs(HmacSecretArgs::class.java)
        withSecurityKey(invoke) { device ->
            WebAuthnClient.create(device, null).use { client ->
                val options = PublicKeyCredentialRequestOptions.fromMap(
                    mapOf(
                        "challenge" to urlEncode(random(32)),
                        "rpId" to args.rpId,
                        "allowCredentials" to args.credentialIds.map {
                            mapOf("type" to "public-key", "id" to urlEncode(decode(it)))
                        },
                        "userVerification" to "required",
                        "extensions" to mapOf(
                            "prf" to mapOf("eval" to mapOf("first" to urlEncode(decode(args.salt)))),
                        ),
                    ),
                )
                val credential = client.getAssertion(
                    ClientDataProvider.fromHash(random(32)),
                    options,
                    args.rpId,
                    args.pin?.toCharArray(),
                    null,
                )
                val prf = credential.clientExtensionResults?.toMap(SerializationType.JSON)?.get("prf") as? Map<*, *>
                val first = (prf?.get("results") as? Map<*, *>)?.get("first") as? String
                    ?: throw IllegalStateException("This security key did not return a secret (does it support hmac-secret?)")
                JSObject().apply {
                    put("credentialId", encode(credential.rawId))
                    put("output", encode(Base64.decode(first, URL_SAFE)))
                }
            }
        }
    }

    /**
     * Wait up to a minute for a security key, plugged in over USB or held to
     * the phone for NFC, and run `work` with the first one that shows up, off
     * the main thread. Discovery stops once it is done either way.
     */
    private fun withSecurityKey(invoke: Invoke, work: (YubiKeyDevice) -> JSObject) {
        val manager = YubiKitManager(activity)
        val finished = AtomicBoolean(false)
        val started = AtomicBoolean(false)

        fun finish(settle: () -> Unit) {
            if (!finished.compareAndSet(false, true)) return
            main.post {
                manager.stopUsbDiscovery()
                try {
                    manager.stopNfcDiscovery(activity)
                } catch (_: Exception) {
                    // NFC was never started.
                }
            }
            settle()
        }

        fun take(device: YubiKeyDevice) {
            if (finished.get() || !started.compareAndSet(false, true)) return
            io.execute {
                try {
                    val result = work(device)
                    finish { invoke.resolve(result) }
                } catch (e: Exception) {
                    finish { invoke.reject(describe(e)) }
                }
            }
        }

        manager.startUsbDiscovery(
            UsbConfiguration().handlePermissions(true).setDeviceFilter(FidoKeys),
            Callback<UsbYubiKeyDevice> { take(it) },
        )
        try {
            manager.startNfcDiscovery(NfcConfiguration(), activity, Callback<NfcYubiKeyDevice> { take(it) })
        } catch (_: NfcNotAvailable) {
            // No NFC on this phone, or it is off: USB still works.
        }
        main.postDelayed({
            finish { invoke.reject("No security key was found. Plug it in, or hold it to the back of the phone.") }
        }, 60_000)
    }

    private fun describe(e: Exception): String = when (e) {
        is PinRequiredClientError -> "Enter the security key's PIN"
        else -> e.message ?: "The security key request failed"
    }

    /** Any USB device with a HID interface, which is how FIDO2 keys connect. */
    private object FidoKeys : DeviceFilter() {
        override fun checkUsbDevice(usbManager: UsbManager, usbDevice: UsbDevice): Boolean =
            (0 until usbDevice.interfaceCount).any {
                usbDevice.getInterface(it).interfaceClass == UsbConstants.USB_CLASS_HID
            }
    }

    private fun random(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(text: String): ByteArray = Base64.decode(text, Base64.DEFAULT)

    private fun urlEncode(bytes: ByteArray) = Base64.encodeToString(bytes, URL_SAFE)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM = "AES/GCM/NoPadding"
        private const val INVALIDATED = "invalidated"
        private const val MISSING = "missing"
        private const val URL_SAFE = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    }
}
