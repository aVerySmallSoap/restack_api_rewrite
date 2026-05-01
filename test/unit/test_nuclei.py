import unittest
from pathlib import Path

from dotenv import load_dotenv

from app.modules.utils.utils import text_io_to_dict_list


class TestZap(unittest.TestCase):
    PROJECT_ROOT = Path.cwd().parent
    load_dotenv()
    target = "35c08a0d-b653-418f-a20f-49f66e28ef7d.json"

    def test_load_json(self):
        with open(f"{self.PROJECT_ROOT}/app/reports/nuclei/{self.target}", "r") as f:
            self.assertIsNotNone(f.read())

    def test_nuclei_parse(self):
        # important: template, template-id, info, url, matched-at, request, response (filter out text/html),
        # curl-command
        # info: name, tags, description, reference, severity, classification
        # info['classification']: cve-id (nullable, potential list), cwe-id (nullable, potential list)
        _json_items: list[dict]
        _returnable: list[dict] = []
        with open(f"{self.PROJECT_ROOT}/app/reports/nuclei/{self.target}", "r") as f:
            _json_items = text_io_to_dict_list(f)
            for record in _json_items:
                _returnable.append({
                    "template": record["template"],
                    "templateId": record["template-id"],
                    "info": {
                        "name": record["info"]["name"],
                        "tags": record["info"]["tags"],
                        "description": record["info"].get("description", None),
                        "reference": record["info"].get("reference", None),
                        "severity": record["info"]["severity"],
                        "classification": {
                            "cve-id": record["info"]["classification"]["cve-id"] if record["info"]["classification"]["cve-id"] else None,
                            "cwe-id": record["info"]["classification"]["cwe-id"] if record["info"]["classification"]["cwe-id"] else None,
                        } if record["info"].get("classification") else None
                    },
                    "url": record["url"],
                    "matchedAt": record["matched-at"],
                    "request": record["request"],
                    "curlCommand": record.get("curl-command", None),
                })
        self.assertIsNotNone(_returnable)
        self.assertFalse(_returnable.__len__() <= 0)