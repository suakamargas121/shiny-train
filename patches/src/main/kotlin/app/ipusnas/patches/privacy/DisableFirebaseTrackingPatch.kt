package app.ipusnas.patches.privacy

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstruction
import app.morphe.patcher.extensions.InstructionExtensions.instructionsOrNull
import app.morphe.patcher.patch.ResourcePatchContext
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.patch.resourcePatch
import app.ipusnas.patches.shared.Constants.COMPATIBILITY_IPUSNAS
import app.ipusnas.patches.shared.fingerprintOrNull
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.ReferenceInstruction

/**
 * Disables Google Firebase Analytics collection and removes the Firebase
 * Cloud Messaging (push notification) components from the app.
 *
 * The manifest changes mirror what the original smali pipeline did:
 *  - add `firebase_analytics_collection_deactivated=true`
 *  - add `google_analytics_adid_collection_enabled=false`
 *  - remove FCM receivers/services and Google Analytics measurement components
 */
private val disableFirebaseManifestPatch = resourcePatch {
    compatibleWith(COMPATIBILITY_IPUSNAS)

    execute {
        val manifest = get("AndroidManifest.xml")
        val content = manifest.readText()

        // Self-closing measurement components.
        var patched = content.replace(
            Regex(
                """<receiver[^>]*android:name="com\.google\.android\.gms\.measurement\.AppMeasurementReceiver"[^>]*/>"""
            ),
            ""
        )
        patched = patched.replace(
            Regex(
                """<service[^>]*android:name="com\.google\.android\.gms\.measurement\.AppMeasurementService"[^>]*/>"""
            ),
            ""
        )
        patched = patched.replace(
            Regex(
                """<service[^>]*android:name="com\.google\.android\.gms\.measurement\.AppMeasurementJobService"[^>]*/>"""
            ),
            ""
        )

        // Multi-line FCM components (service / receiver with intent-filter children).
        patched = patched.replace(
            Regex(
                """\s*<service[^>]*android:name="mam\.reader\.ilibrary\.fcm\.MyFirebaseMessagingService"[^>]*>.*?</service>""",
                RegexOption.DOT_MATCHES_ALL
            ),
            ""
        )
        patched = patched.replace(
            Regex(
                """\s*<service[^>]*android:name="com\.google\.firebase\.messaging\.FirebaseMessagingService"[^>]*>.*?</service>""",
                RegexOption.DOT_MATCHES_ALL
            ),
            ""
        )
        patched = patched.replace(
            Regex(
                """\s*<receiver[^>]*android:name="com\.google\.firebase\.iid\.FirebaseInstanceIdReceiver"[^>]*>.*?</receiver>""",
                RegexOption.DOT_MATCHES_ALL
            ),
            ""
        )

        // FCM default notification channel meta-data can stay; it is inert.
        manifest.writeText(patched)

        // Add analytics deactivation meta-data to the <application> element.
        document("AndroidManifest.xml").use { document ->
            val application = document.getElementsByTagName("application").item(0)
            fun addMetaData(name: String, value: String) {
                val meta = document.createElement("meta-data")
                meta.setAttribute("android:name", name)
                meta.setAttribute("android:value", value)
                application.appendChild(meta)
            }
            addMetaData("firebase_analytics_collection_deactivated", "true")
            addMetaData("google_analytics_adid_collection_enabled", "false")
        }
    }
}

/**
 * The app registers the FCM token in LandingPageAct (B() in 2.1.4, C() in
 * 2.1.6) right after creating notification channels. With the FCM service
 * removed from the manifest the token registration is pointless and can
 * throw, so we skip only the token block.
 *
 * In 2.1.6 C()V the instruction layout is:
 *   insns 0..55   notification-channel creation (kept)
 *   insn 56..57   FirebaseApp null checks
 *   insn 58..69   FirebaseMessaging.setAutoInitEnabled / getToken / subscribe
 *   insn 69       return-void (end of channel path)
 *
 * Inserting `return-void` at index 0 would also kill channel creation, so the
 * patch instead jumps over the Firebase block: a `goto` whose target is the
 * method's own trailing return keeps 0..57 intact and skips 58..69.
 */
private val neuterLandingPageFcmPatch = bytecodePatch {
    compatibleWith(COMPATIBILITY_IPUSNAS)

    execute {
        val method = fingerprintOrNull(
            LandingPageFcmTokenFingerprint,
            LandingPageFcmTokenFingerprintV216,
        )

        val instructions = method.instructionsOrNull?.toList() ?: emptyList()

        // In 2.1.6 C()V the layout is (code-unit offsets in parentheses):
        //   0..55   notification-channel creation            (kept)
        //   56..57  FirebaseApp null checks                  (harmless)
        //   58      const-class FirebaseMessaging            (skip from here)
        //   58..69  setAutoInitEnabled/getToken/subscribe    (skipped)
        //   69      return-void                              (jump target)
        // We insert a goto right before the Firebase const-class that lands on
        // the first return-void at or after it. Offsets are in 16-bit code
        // units (invoke = 3, const-class = 2), NOT instruction indices.
        val firebaseIdx = instructions.indexOfFirst {
            it.opcode == Opcode.CONST_CLASS &&
                (it as? ReferenceInstruction)?.reference.toString().contains("FirebaseMessaging")
        }

        val returnIdx = (firebaseIdx until instructions.size)
            .firstOrNull { instructions[it].opcode == Opcode.RETURN_VOID }

        val skipUnits = returnIdx?.let {
            instructions.subList(firebaseIdx, it).sumOf { insn -> insn.codeUnits } + 2
        } ?: 0

        if (firebaseIdx > 0 && returnIdx != null && skipUnits in 3..126) {
            method.addInstruction(firebaseIdx, "goto +$skipUnits")
        } else {
            // Layout unexpected — fall back to neutering the whole method.
            // Channels get recreated on every activity launch in this app.
            method.addInstruction(0, "return-void")
        }
    }
}

@Suppress("unused")
val disableFirebaseTrackingPatch = bytecodePatch(
    name = "Disable Firebase Analytics and FCM",
    description = "Disables Google Firebase Analytics tracking and removes Firebase Cloud Messaging push notifications.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_IPUSNAS)

    dependsOn(
        disableFirebaseManifestPatch,
        neuterLandingPageFcmPatch,
    )

    execute { }
}
