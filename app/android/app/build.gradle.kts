import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing (audit G-11; docs/release.md §8): from android/key.properties (untracked,
// gitignored) or the YEW_RELEASE_* environment, never the debug key. A release build without
// a signing config fails instead of producing a debug-signed artifact.
val keyProps = Properties().also { p ->
    val f = rootProject.file("key.properties")
    if (f.exists()) f.inputStream().use { p.load(it) }
}
fun signing(name: String): String? = keyProps.getProperty(name) ?: System.getenv("YEW_RELEASE_" + name.uppercase())
val releaseStoreFile = signing("storeFile")
val hasReleaseSigning = releaseStoreFile != null

android {
    namespace = "cash.ycash.yew.yew_app"
    compileSdk = flutter.compileSdkVersion
    // Pinned NDK (plan §7 W0a); Flutter 3.47.5 default. scripts/build-core-android.sh uses the same.
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "cash.ycash.yew.yew_app"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(releaseStoreFile!!)
                storePassword = signing("storePassword")
                keyAlias = signing("keyAlias")
                keyPassword = signing("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // Only the release keystore signs a release; with none configured the build fails
            // below rather than falling back to the debug key.
            signingConfig = if (hasReleaseSigning) signingConfigs.getByName("release") else null
        }
    }
}

tasks.configureEach {
    if (!hasReleaseSigning && (name.startsWith("assembleRelease") || name.startsWith("bundleRelease") || name.startsWith("packageRelease"))) {
        doFirst {
            throw GradleException(
                "YEW: no release signing config. Create android/key.properties (storeFile, storePassword, " +
                    "keyAlias, keyPassword) or set YEW_RELEASE_STOREFILE/STOREPASSWORD/KEYALIAS/KEYPASSWORD " +
                    "(docs/release.md §8). Release builds are never signed with the debug key."
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
