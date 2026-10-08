from datetime import datetime, timedelta, timezone


class ComplianceService:

    SENSITIVE_TERMS = {
        "personal",
        "pii",
        "password",
        "credential",
        "financial",
        "health",
        "payment",
        "account",
        "secret",
        "token",
        "customer",
        "employee",
        "data",
    }

    def evaluate(self, rows):

        # =========================================================
        # 1. BUILD INCIDENT TEXT
        # =========================================================

        text = " ".join(
            str(r.get(k, ""))
            for r in rows
            for k in (
                "incident_type",
                "threat_class",
                "command",
                "evidence",
                "extracted_evidence",
            )
        ).lower()

        # =========================================================
        # 2. CHECK SEVERITY
        # =========================================================

        severities = {
            str(r.get("severity", "")).lower()
            for r in rows
        }

        high_critical = bool(
            severities & {"critical", "high"}
        )

        # =========================================================
        # 3. CHECK SENSITIVE DATA INDICATORS
        # =========================================================

        matched = sorted(
            term
            for term in self.SENSITIVE_TERMS
            if term in text
        )

        sensitive_data_detected = (
            len(matched) > 0
        )

        # =========================================================
        # 4. DETERMINE POTENTIAL NOTIFICATION TRIGGER
        #
        # ClockGuard activates the notification window ONLY
        # when a potential notification trigger is detected.
        # =========================================================

        potential_notification_trigger = (
            high_critical
            or sensitive_data_detected
        )

        reasons = []

        if high_critical:
            reasons.append(
                "High/Critical severity requires formal incident-response review."
            )

        if sensitive_data_detected:
            reasons.append(
                "Potential sensitive-data or credential exposure indicators were observed in the supplied evidence text."
            )

        if potential_notification_trigger:
            reasons.append(
                "Potential regulatory notification trigger detected. "
                "ClockGuard has activated the 72-hour notification review window."
            )

        if not reasons:
            reasons.append(
                "No specific regulatory notification trigger was determined from the supplied fields alone."
            )

        # =========================================================
        # 5. 72-HOUR NOTIFICATION WINDOW
        #
        # IMPORTANT:
        #
        # The clock DOES NOT start merely because an incident
        # is selected.
        #
        # It starts only after ClockGuard's compliance screening
        # detects a potential notification trigger.
        #
        # For this prototype, the trigger-detection time is used
        # as the notification-window start time.
        # =========================================================

        notification_triggered = False

        notification_status = "NOT ACTIVE"

        breach_awareness_time = None

        notification_deadline = None

        hours_remaining = None

        deadline_passed = False

        if potential_notification_trigger:

            notification_triggered = True

            # Clock starts at the moment ClockGuard detects
            # the potential notification trigger.

            awareness_time = datetime.now(
                timezone.utc
            )

            deadline_time = (
                awareness_time
                + timedelta(hours=72)
            )

            breach_awareness_time = (
                awareness_time
                .isoformat()
                .replace("+00:00", "Z")
            )

            notification_deadline = (
                deadline_time
                .isoformat()
                .replace("+00:00", "Z")
            )

            hours_remaining = 72.0

            notification_status = (
                "72-HOUR WINDOW ACTIVE"
            )

            deadline_passed = False

        # =========================================================
        # 6. RETURN COMPLIANCE RESULT
        # =========================================================

        return {

            # =====================================================
            # EXISTING COMPLIANCE FIELDS
            # =====================================================

            "status":
                (
                    "Review Required"
                    if potential_notification_trigger
                    else "No Trigger Determined"
                ),

            "matched_indicators":
                matched,

            "reasons":
                reasons,

            "jurisdiction":
                "Not provided",

            "regulation":
                (
                    "GDPR-style 72-hour screening"
                    if potential_notification_trigger
                    else "Not determined"
                ),

            "manual_review_required":
                True,

            # =====================================================
            # NOTIFICATION TRIGGER
            # =====================================================

            "potential_notification_trigger":
                potential_notification_trigger,

            "notification_triggered":
                notification_triggered,

            "notification_requirement":
                (
                    "Potential regulatory notification — "
                    "review required"
                    if potential_notification_trigger
                    else "No notification trigger detected"
                ),

            "notification_regulation":
                (
                    "GDPR-style 72-hour notification screening"
                    if potential_notification_trigger
                    else "Not determined"
                ),

            # =====================================================
            # 72-HOUR WINDOW
            # =====================================================

            "notification_window_hours":
                (
                    72
                    if potential_notification_trigger
                    else None
                ),

            "breach_awareness_time":
                breach_awareness_time,

            "notification_deadline":
                notification_deadline,

            "hours_remaining":
                hours_remaining,

            "notification_status":
                notification_status,

            "deadline_passed":
                deadline_passed,

            # =====================================================
            # CLOCK BASIS
            # =====================================================

            "clock_basis":
                (
                    "ClockGuard detected a potential regulatory "
                    "notification trigger during compliance screening. "
                    "The 72-hour notification review window was "
                    "activated at trigger-detection time."
                    if potential_notification_trigger
                    else
                    "Notification clock is not active because "
                    "no potential regulatory notification trigger "
                    "was detected."
                ),

            # =====================================================
            # DISCLAIMER
            # =====================================================

            "disclaimer":
                (
                    "This is an operational screening aid, not legal "
                    "advice. The 72-hour clock is a prototype "
                    "notification-window indicator and does not "
                    "establish the actual statutory deadline. Confirm "
                    "applicable law, jurisdiction, contracts, affected "
                    "data, breach-awareness time and notification "
                    "requirements with the appropriate legal/compliance "
                    "team."
                ),
        }