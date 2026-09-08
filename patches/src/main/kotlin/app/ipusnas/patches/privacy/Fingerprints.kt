package app.ipusnas.patches.privacy

import app.morphe.patcher.Fingerprint
import com.android.tools.smali.dexlib2.AccessFlags

/**
 * Fingerprints used by the privacy patches.
 *
 * The fingerprints are intentionally minimal and prefer stable identifiers
 * (package names, method names) over obfuscated helper classes.
 *
 * 2.1.4 (versionCode 210000020) targets were verified originally. In 2.1.6
 * (versionCode 210000027) the developer re-ran obfuscation and several
 * methods were renamed; the V216 fingerprints below cover those. The patch
 * code tries the 2.1.4 fingerprint first and falls back to the 2.1.6 one.
 */
object SecurityReporterBreachFingerprint : Fingerprint(
    definingClass = "Lmam/reader/ilibrary/security/SecurityReporter;",
    name = "reportBreach",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC, AccessFlags.FINAL),
    returnType = "V",
    parameters = listOf("Ljava/lang/String;"),
)

object SecurityReporterIntegrityFingerprint : Fingerprint(
    definingClass = "Lmam/reader/ilibrary/security/SecurityReporter;",
    name = "reportIntegrityFailure",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "V",
    parameters = listOf("Ljava/lang/String;"),
)

/**
 * 2.1.6: reportIntegrityFailure was reobfuscated to "b" and is now static.
 * Identified by its body: builds the "⚠️ INTEGRITY CHECK FAILED ⚠️" message,
 * encrypts it and dispatches it to the Telegram reporter coroutine.
 */
object SecurityReporterIntegrityFingerprintV216 : Fingerprint(
    definingClass = "Lmam/reader/ilibrary/security/SecurityReporter;",
    name = "b",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
    returnType = "V",
    parameters = listOf("Ljava/lang/String;"),
)

// NOTE: SecurityNative (isRooted / isDebugged / verifyApkIntegrity) no longer
// exists anywhere in the 2.1.6 dex files. These fingerprints are kept only for
// reference; no shipped patch currently uses them.
object SecurityNativeIsRootedFingerprint : Fingerprint(
    definingClass = "Lcom/aksaramaya/ilibrarycore/security/SecurityNative;",
    name = "isRooted",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Z",
)

object SecurityNativeIsDebuggedFingerprint : Fingerprint(
    definingClass = "Lcom/aksaramaya/ilibrarycore/security/SecurityNative;",
    name = "isDebugged",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Z",
)

object SecurityNativeVerifyApkIntegrityFingerprint : Fingerprint(
    definingClass = "Lcom/aksaramaya/ilibrarycore/security/SecurityNative;",
    name = "verifyApkIntegrity",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Z",
    parameters = listOf("Ljava/lang/String;"),
)

object LicenseClientPerformLocalInstallerCheckFingerprint : Fingerprint(
    definingClass = "Lcom/pairip/licensecheck/LicenseClient;",
    name = "performLocalInstallerCheck",
    accessFlags = listOf(AccessFlags.PRIVATE),
    returnType = "Z",
)

/**
 * LandingPageAct.B() registers the device for FCM push notifications.
 * Neutering it stops token registration (which is meaningless once the
 * FCM components are removed from the manifest).
 */
object LandingPageFcmTokenFingerprint : Fingerprint(
    definingClass = "Lmam/reader/ilibrary/landing/LandingPageAct;",
    name = "B",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "V",
    parameters = emptyList(),
)

/**
 * 2.1.6: the FCM token registration method in LandingPageAct was reobfuscated
 * from "B" to "C". Identified by its body: FirebaseMessaging.setAutoInitEnabled,
 * getToken(), the "fcm_token" const-string and LandingViewModel.updateFcmToken,
 * after creating the notification channels.
 */
object LandingPageFcmTokenFingerprintV216 : Fingerprint(
    definingClass = "Lmam/reader/ilibrary/landing/LandingPageAct;",
    name = "C",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "V",
    parameters = emptyList(),
)
