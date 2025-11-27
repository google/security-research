import org.gradle.api.tasks.Exec

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.google.android.kernelctf.shellserver"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.google.android.kernelctf.shellserver"
        minSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("release") {
            keyAlias = "key-alias"
            keyPassword = "password"
            storeFile = file("release-key.keystore")
            storePassword = "password"
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

tasks.register<Exec>("generateKeystore") {
    group = "signing"
    description = "Generates the release keystore if missing"

    val keystoreFile = file("release-key.keystore")

    // Check if keystore exists BEFORE task execution
    onlyIf {
        !keystoreFile.exists()
    }

    doFirst {
        println("Generating keystore at ${keystoreFile.absolutePath}...")
    }

    commandLine(
        "keytool",
        "-genkey",
        "-v",
        "-keystore", keystoreFile.absolutePath,
        "-alias", project.findProperty("KEY_ALIAS") ?: "key-alias",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", project.findProperty("KEYSTORE_PASSWORD") ?: "password",
        "-keypass", project.findProperty("KEY_PASSWORD") ?: "password",
        "-dname", "CN=com.google.android.kernelctf.shellserver, O=Google LLC, L=Mountain View, S=CA, C=US"
    )
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.activity)
    implementation(libs.constraintlayout)
}
