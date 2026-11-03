import unittest
from unittest import mock

from password_analyzer.analyzer import analyze, charset_size, entropy, find_issues
from password_analyzer.hibp import parse_response, sha1_split, times_pwned


class TestAnalyzer(unittest.TestCase):
    def test_charset_size(self):
        self.assertEqual(charset_size("abc"), 26)
        self.assertEqual(charset_size("aB3"), 62)
        self.assertEqual(charset_size("aB3!"), 95)

    def test_entropy_empty(self):
        self.assertEqual(entropy(""), 0.0)

    def test_common_password_is_very_weak(self):
        result = analyze("password")
        self.assertEqual(result.score, 0)
        self.assertTrue(any("más usadas" in i for i in result.issues))

    def test_detects_sequences_and_repeats(self):
        self.assertTrue(any("secuencia" in i for i in find_issues("xx1234yy")))
        self.assertTrue(any("Repite" in i for i in find_issues("aaab")))
        self.assertTrue(any("año" in i for i in find_issues("Pepe1998")))

    def test_strong_password(self):
        result = analyze("v7#Kq!zR2$mW9pL&xT")
        self.assertEqual(result.score, 4)
        self.assertEqual(result.issues, [])


class TestHIBP(unittest.TestCase):
    def test_sha1_split(self):
        # SHA-1 de "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        self.assertEqual(sha1_split("password"),
                         ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"))

    def test_parse_response(self):
        body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365"
        self.assertEqual(parse_response(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 9659365)
        self.assertEqual(parse_response(body, "FFFF"), 0)

    def test_only_prefix_is_sent(self):
        """Verifica el k-anonimato: la URL solo lleva 5 caracteres del hash."""
        fake = mock.MagicMock()
        fake.__enter__.return_value.read.return_value = b""
        with mock.patch("urllib.request.urlopen", return_value=fake) as urlopen:
            times_pwned("password")
        url = urlopen.call_args[0][0].full_url
        self.assertTrue(url.endswith("/range/5BAA6"))


if __name__ == "__main__":
    unittest.main()
