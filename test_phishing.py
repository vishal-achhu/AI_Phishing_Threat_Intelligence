import unittest
from email_analyzer import analyze_email, load_demo_emails
from ioc_extractor import extract_iocs
from url_analyzer import analyze_url
from response_engine import build_response_plan, simulate_block
from ai_copilot import local_explanation

class PhishingTests(unittest.TestCase):
    def test_suspicious_email_scores_higher_than_benign(self):
        samples = load_demo_emails()
        suspicious = analyze_email(samples[0]["subject"], samples[0]["sender"], samples[0]["headers"], samples[0]["body"])
        benign = analyze_email(samples[1]["subject"], samples[1]["sender"], samples[1]["headers"], samples[1]["body"])
        self.assertGreater(suspicious["risk_score"], benign["risk_score"])
        self.assertIn(suspicious["risk_level"], ["High", "Critical"])

    def test_ioc_extraction(self):
        result = extract_iocs("Visit http://198.51.100.9/login and contact evil.example.test. Hash: " + "a"*64)
        self.assertIn("198.51.100.9", result["ips"])
        self.assertTrue(result["urls"])
        self.assertIn("evil.example.test", result["domains"])
        self.assertIn("a"*64, result["hashes"])

    def test_url_heuristics(self):
        result = analyze_url("http://198.51.100.9/login")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "Medium")

    def test_response_is_simulated(self):
        sample = load_demo_emails()[0]
        analysis = analyze_email(sample["subject"], sample["sender"], sample["headers"], sample["body"])
        self.assertTrue(build_response_plan(analysis))
        self.assertEqual(simulate_block([], "example.test"), ["example.test"])

    def test_local_copilot(self):
        sample = load_demo_emails()[0]
        analysis = analyze_email(sample["subject"], sample["sender"], sample["headers"], sample["body"])
        self.assertIn("Analyst assessment", local_explanation(analysis))

if __name__ == "__main__":
    unittest.main()
