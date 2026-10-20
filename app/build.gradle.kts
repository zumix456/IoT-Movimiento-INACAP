plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "cl.inacap.iotmovimiento"
    compileSdk = 35

    defaultConfig {
        applicationId = "cl.inacap.iotmovimiento"
        minSdk = 26
        targetSdk = 32
        versionCode = 2
        versionName = "2.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}
