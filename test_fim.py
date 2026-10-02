import os
import sys
import json
import unittest
import tempfile
import shutil
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fim


class TestCanaryGuardEDR(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.file1 = os.path.join(self.test_dir, "config.txt")
        self.file2 = os.path.join(self.test_dir, "data.txt")
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("Original config content")
        with open(self.file2, "w", encoding="utf-8") as f:
            f.write("Original data content")
        self.baseline_path = os.path.join(self.test_dir, "baseline.json")
        fim.CONFIG["baseline_file"] = self.baseline_path
        fim.CONFIG["canary_directories"] = []
        fim.CONFIG["webhook_url"] = ""

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if os.path.exists(self.baseline_path):
            os.remove(self.baseline_path)
        key_file = fim.CONFIG.get("hmac_secret_file", ".fim_key")
        if os.path.exists(key_file):
            os.remove(key_file)

    def test_hashes_consistent(self):
        raw1, hmac1 = fim.compute_hashes(self.file1)
        raw2, hmac2 = fim.compute_hashes(self.file1)
        self.assertEqual(raw1, raw2)
        self.assertEqual(hmac1, hmac2)
        self.assertIsNotNone(raw1)
        self.assertEqual(len(raw1), 64)
        self.assertEqual(len(hmac1), 64)

    def test_hashes_different_files(self):
        raw1, _ = fim.compute_hashes(self.file1)
        raw2, _ = fim.compute_hashes(self.file2)
        self.assertNotEqual(raw1, raw2)

    def test_hashes_nonexistent_file(self):
        raw, signed_hmac = fim.compute_hashes("/nonexistent/file.txt")
        self.assertIsNone(raw)
        self.assertIsNone(signed_hmac)

    def test_create_baseline(self):
        baseline = fim.create_baseline([self.test_dir])
        self.assertEqual(baseline["meta"]["total_files"], 2)
        self.assertIn("files", baseline)
        self.assertTrue(os.path.exists(self.baseline_path))

    def test_detect_modified_file(self):
        fim.create_baseline([self.test_dir])
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("TAMPERED CONTENT!")
        results = fim.check_integrity([self.test_dir])
        self.assertEqual(len(results["modified"]), 1)
        self.assertEqual(results["summary"]["status"], "ALERT")

    def test_detect_deleted_file(self):
        fim.create_baseline([self.test_dir])
        os.remove(self.file1)
        results = fim.check_integrity([self.test_dir])
        self.assertEqual(len(results["deleted"]), 1)
        self.assertEqual(results["summary"]["status"], "ALERT")

    def test_detect_new_file(self):
        fim.create_baseline([self.test_dir])
        new_file = os.path.join(self.test_dir, "newfile.txt")
        with open(new_file, "w", encoding="utf-8") as f:
            f.write("I am a new file")
        results = fim.check_integrity([self.test_dir])
        self.assertEqual(len(results["new_files"]), 1)

    def test_clean_result(self):
        fim.create_baseline([self.test_dir])
        results = fim.check_integrity([self.test_dir])
        self.assertEqual(results["summary"]["status"], "CLEAN")
        self.assertEqual(len(results["modified"]), 0)

    def test_shannon_entropy_calculation(self):
        zero_entropy_file = os.path.join(self.test_dir, "zeros.bin")
        with open(zero_entropy_file, "wb") as f:
            f.write(b"A" * 1024)
        entropy_low = fim.calculate_shannon_entropy(zero_entropy_file)
        self.assertEqual(entropy_low, 0.0)

        random_data_file = os.path.join(self.test_dir, "random.bin")
        with open(random_data_file, "wb") as f:
            f.write(os.urandom(4096))
        entropy_high = fim.calculate_shannon_entropy(random_data_file)
        self.assertGreater(entropy_high, 7.0)

    def test_canary_token_tampering(self):
        canary_dir = os.path.join(self.test_dir, "canary")
        fim.CONFIG["canary_directories"] = [canary_dir]
        fim.create_baseline([self.test_dir])
        token_name = fim.CONFIG.get("canary_filename", ".canary_token.dat")
        token_file = os.path.join(canary_dir, token_name)
        self.assertTrue(os.path.exists(token_file))
        with open(token_file, "w", encoding="utf-8") as f:
            f.write("TRIPPED_CANARY")
        results = fim.check_integrity([self.test_dir])
        self.assertEqual(len(results["canary_tampered"]), 1)
        self.assertEqual(results["summary"]["status"], "ALERT")


if __name__ == "__main__":
    unittest.main(verbosity=2)