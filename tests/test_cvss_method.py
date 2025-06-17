import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import pandas as pd
import asyncio
from src.scan.cvss_score import generate_cvss, safe_cvss_score


class TestCVSSScore(unittest.TestCase):

    @patch("src.scan.cvss_score.read_file_prompt")
    @patch("src.scan.cvss_score.reasoning_prompt")
    @patch("src.scan.cvss_score.model")
    def test_generate_cvss_success(self, mock_model, mock_reasoning, mock_read_prompt):
        # Sample input row
        row = pd.Series({
            "id": "VULN-001",
            "title": "Example Vulnerability",
            "description": "An example CVE issue description."
        })

        # Mock prompt loading
        mock_read_prompt.return_value = "System Prompt"
        mock_reasoning.return_value = "Human Prompt"

        # Mock model response
        mock_response = MagicMock()
        mock_response.content = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        mock_model.ainvoke = AsyncMock(return_value=mock_response)

        # Run async function
        result = asyncio.run(generate_cvss(row))
        self.assertTrue(result.startswith("CVSS:3.1"))

    @patch("src.scan.cvss_score.read_file_prompt", side_effect=Exception("File read error"))
    @patch("src.scan.cvss_score.model")
    def test_generate_cvss_failure(self, mock_model, mock_read_prompt):
        row = pd.Series({
            "id": "VULN-001",
            "title": "Bad Vulnerability"
        })
        result = asyncio.run(generate_cvss(row))
        self.assertIsNone(result)

    def test_safe_cvss_score_valid(self):
        cvss_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = safe_cvss_score(cvss_string)
        self.assertIsInstance(score, float)
        self.assertGreater(score, 0)

    def test_safe_cvss_score_invalid(self):
        bad_cvss = "INVALID:STRING"
        score = safe_cvss_score(bad_cvss)
        self.assertIsNone(score)

    def test_safe_cvss_score_none(self):
        score = safe_cvss_score(None)
        self.assertIsNone(score)


if __name__ == '__main__':
    unittest.main()
