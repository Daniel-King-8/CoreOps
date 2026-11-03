import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.reach.unlock"
    compileSdk = 37

    defaultConfig {
        // Tauri's own floor. The fingerprint key needs 24
        // (setInvalidatedByBiometricEnrollment); newer calls are guarded.
        minSdk = 24

        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.9.0")
    implementation("androidx.appcompat:appcompat:1.6.0")
    // BiometricPrompt with a CryptoObject (latest stable).
    implementation("androidx.biometric:biometric:1.1.0")
    // FIDO2 security keys over USB and NFC.
    implementation("com.yubico.yubikit:android:3.2.1")
    implementation("com.yubico.yubikit:fido:3.2.1")
    implementation(project(":tauri-android"))
}
