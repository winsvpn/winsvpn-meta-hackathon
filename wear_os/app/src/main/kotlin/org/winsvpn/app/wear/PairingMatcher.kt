package org.winsvpn.app.wear

/**
 * The pairing gate that keeps this watch bound to the signed release phone app.
 *
 * The Wearable Data Layer delivers between two nodes only when they run the
 * SAME package signed with the SAME certificate. This watch is
 * `org.winsvpn.app`, so it pairs with a phone node only if that phone is also
 * `org.winsvpn.app` carrying the release signing cert. The phone build separates
 * its non-release variants into distinct application ids -- `org.winsvpn.app.debug`
 * and `org.winsvpn.app.test` -- precisely so the platform refuses to pair them
 * with this watch: a different application id is already a different package,
 * and the shared-package match fails.
 *
 * This object states that contract as an explicit, testable predicate rather
 * than leaving it implicit, so a future change that starts accepting a debug,
 * QA, or unrelated phone identity is caught at the boundary instead of silently
 * unpairing or, worse, pairing with a non-release build.
 *
 * The predicate is exact-match only. It never accepts a prefix or a look-alike,
 * because an acceptance rule that could grow to cover `.debug`/`.test` is the
 * failure mode this object exists to rule out.
 */
object PairingMatcher {

    /** The only phone application id this watch may pair with. */
    const val RELEASE_PACKAGE = "org.winsvpn.app"

    /** Phone application ids that must be refused (the phone build's own names). */
    const val DEBUG_PACKAGE = "org.winsvpn.app.debug"
    const val QA_PACKAGE = "org.winsvpn.app.test"
    const val STALE_TV_PACKAGE = "org.winsvpn.app.tv"

    /**
     * Result of evaluating a candidate companion phone identity.
     *
     * [Accepted] is only ever produced for exactly [RELEASE_PACKAGE].
     */
    sealed interface Verdict {
        data object Accepted : Verdict
        data class Refused(val reason: String) : Verdict
    }

    /**
     * True only when [applicationId] is exactly the release phone package.
     *
     * @param applicationId the phone's application id, or null when the watch
     *   has not learned one.
     */
    fun isRelease(applicationId: String?): Boolean = applicationId == RELEASE_PACKAGE

    /** A status or user command belongs only to the currently selected phone. */
    fun matchesSelectedNode(sourceNodeId: String?, selectedNodeId: String?): Boolean =
        !sourceNodeId.isNullOrBlank() && sourceNodeId == selectedNodeId

    /**
     * Classify a candidate companion phone identity.
     *
     * @return [Verdict.Accepted] only for exactly [RELEASE_PACKAGE]; otherwise a
     *   [Verdict.Refused] naming why.
     */
    fun evaluate(applicationId: String?): Verdict = when (applicationId) {
        RELEASE_PACKAGE -> Verdict.Accepted
        DEBUG_PACKAGE -> Verdict.Refused("debug companion build")
        QA_PACKAGE -> Verdict.Refused("QA companion build")
        STALE_TV_PACKAGE -> Verdict.Refused("contaminated TV companion identity")
        null -> Verdict.Refused("no phone application id")
        else -> Verdict.Refused("not the release companion build")
    }
}
