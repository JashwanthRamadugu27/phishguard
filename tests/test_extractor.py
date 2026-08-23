"""Unit tests for LinkExtractor and URL defanging."""

from app.defang import defang_url, extract_domain
from app.extractor import LinkExtractor, refang_url


class TestLinkExtractor:
    def test_extract_standard_urls(self):
        content = """
        Hello Team,
        Please review the attached invoice at https://invoicing-portal.com/doc/98234
        Also check the backup server at http://backup.internal-tools.org:8080/files.
        """
        targets = LinkExtractor.extract_urls(content)
        assert len(targets) == 2
        assert targets[0].domain == "invoicing-portal.com"
        assert targets[0].defanged_url == "hxxps://invoicing-portal[.]com/doc/98234"
        assert targets[1].domain == "backup.internal-tools.org"
        assert targets[1].defanged_url == "hxxp://backup[.]internal-tools[.]org:8080/files"

    def test_extract_obfuscated_and_encoded_urls(self):
        content = """
        Urgent: Click here to verify account:
        https%3A%2F%2Fsecure-verify.paypal-security.net%2Flogin%3Fid%3D8832
        """
        targets = LinkExtractor.extract_urls(content)
        assert len(targets) == 1
        assert targets[0].domain == "secure-verify.paypal-security.net"
        assert "hxxps://secure-verify[.]paypal-security[.]net" in targets[0].defanged_url

    def test_extract_defanged_domains(self):
        content = """
        IOC Alert: Observed malware calling out to evil-c2-server[.]ru/beacon.
        Also check phishing-site(.)top/landing.
        """
        targets = LinkExtractor.extract_urls(content)
        assert len(targets) == 2
        domains = [t.domain for t in targets]
        assert "evil-c2-server.ru" in domains
        assert "phishing-site.top" in domains

    def test_extract_from_html_body(self):
        html_email = """
        <html>
            <body>
                <p>Dear Customer,</p>
                <a href="https://chase-security-alert.net/verify">Confirm Identity</a>
                <form action="http://malicious-collector.com/steal" method="POST">
                    <input type="password" name="pwd"/>
                </form>
            </body>
        </html>
        """
        targets = LinkExtractor.extract_urls(html_email)
        assert len(targets) == 2
        domains = [t.domain for t in targets]
        assert "chase-security-alert.net" in domains
        assert "malicious-collector.com" in domains

    def test_deduplicate_urls(self):
        content = """
        https://login.microsoft.com/common/oauth2
        https://login.microsoft.com/common/oauth2
        https://login.microsoft.com/common/oauth2/
        """
        targets = LinkExtractor.extract_urls(content)
        assert len(targets) == 1

    def test_refang_utilities(self):
        assert refang_url("hxxps://bad[.]com/login") == "https://bad.com/login"
        assert refang_url("hxxp://victim(.)co[.]uk") == "http://victim.co.uk"
        assert refang_url("http%3A%2F%2Ftest.com") == "http://test.com"

    def test_defang_utilities(self):
        assert defang_url("http://evil.com") == "hxxp://evil[.]com"
        assert defang_url("https://sub.bank.com/path") == "hxxps://sub[.]bank[.]com/path"
        assert extract_domain("https://sub.domain.com:8443/test") == "sub.domain.com"
