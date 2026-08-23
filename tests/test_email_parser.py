"""Unit tests for the EmailParser and MIME forensic analysis."""

import pytest
from app.email_parser import EmailParser


SAMPLE_EML_RAW = """From: "PayPal Security Team" <alert-update@secure-notifications-paypal.top>
To: victim@company.com
Subject: [URGENT] Verify Your Account Access Within 24 Hours
Date: Sat, 22 Aug 2026 12:00:00 +0000
Message-ID: <12345@secure-notifications-paypal.top>
Authentication-Results: mx.google.com; dkim=fail; spf=fail (google.com: domain of alert-update@secure-notifications-paypal.top does not designate IP)
Content-Type: multipart/alternative; boundary="boundary-xyz"

--boundary-xyz
Content-Type: text/plain; charset="utf-8"

Dear Customer,
We noticed unusual login attempts. Verify your details here:
https://paypal.com.verify-identity-login.top/account

--boundary-xyz
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear Customer,</p>
<a href="https://paypal.com.verify-identity-login.top/account">Click Here to Verify</a>
<p>Thank you, PayPal Security</p>
</body>
</html>
--boundary-xyz--
"""


class TestEmailParser:
    def test_parse_sample_eml(self):
        parsed = EmailParser.parse_eml(SAMPLE_EML_RAW)

        assert parsed.subject == "[URGENT] Verify Your Account Access Within 24 Hours"
        assert parsed.sender_address == "alert-update@secure-notifications-paypal.top"
        assert parsed.sender_domain == "secure-notifications-paypal.top"
        assert parsed.spf_status == "fail"
        assert parsed.dkim_status == "fail"
        assert parsed.is_spoofed_display_name is True  # Claims "PayPal" but domain is not paypal.com
        assert len(parsed.targets) == 1
        assert parsed.targets[0].domain == "paypal.com.verify-identity-login.top"
        assert "hxxps://paypal[.]com[.]verify-identity-login[.]top" in parsed.targets[0].defanged_url

    def test_parse_multipart_with_attachments(self):
        eml_with_attachment = """From: HR Dept <hr@company.com>
To: employee@company.com
Subject: Payroll Update
Content-Type: multipart/mixed; boundary="boundary-mixed"

--boundary-mixed
Content-Type: text/plain; charset="utf-8"

Please review attached spreadsheet.
http://internal-portal.company.com/payroll

--boundary-mixed
Content-Type: application/vnd.ms-excel
Content-Disposition: attachment; filename="Payroll_Update_2026.xlsx.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=
--boundary-mixed--
"""
        parsed = EmailParser.parse_eml(eml_with_attachment)
        assert len(parsed.attachments) == 1
        assert parsed.attachments[0] == "Payroll_Update_2026.xlsx.exe"
        assert len(parsed.targets) == 1
        assert parsed.targets[0].domain == "internal-portal.company.com"

    def test_display_name_spoofing_detection(self):
        assert EmailParser._check_display_name_spoofing("Microsoft 365 Support", "attacker-portal.com") is True
        assert EmailParser._check_display_name_spoofing("Apple ID Alert", "notifications-apple.com") is True
        assert EmailParser._check_display_name_spoofing("Microsoft Account Team", "accountprotection.microsoft.com") is False
