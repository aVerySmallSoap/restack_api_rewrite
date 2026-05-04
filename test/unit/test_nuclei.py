import unittest
from pathlib import Path

from dotenv import load_dotenv
from pydantic import AnyUrl

from app.modules.utils.utils import text_io_to_dict_list
from app.modules.scanners.web.nuclei.nuclei_context import NucleiClassification, NucleiInfo, NucleiRecord


class TestZap(unittest.TestCase):
    PROJECT_ROOT = Path.cwd().parent
    load_dotenv()
    target = "8f093700-83b1-404f-b8f3-1bc4788c270e.json"

    def test_load_json(self):
        with open(f"{self.PROJECT_ROOT}/app/reports/nuclei/{self.target}", "r") as f:
            self.assertIsNotNone(f.read())

    def test_nuclei_parse(self):
        # important: template, template-id, info, url, matched-at, request, response (filter out text/html),
        # curl-command
        # info: name, tags, description, reference, severity, classification
        # info['classification']: cve-id (nullable, potential list), cwe-id (nullable, potential list)
        _json_items: list[dict]
        _returnable: list[NucleiRecord] = []
        with open(f"{self.PROJECT_ROOT}/app/reports/nuclei/{self.target}", "r") as f:
            _json_items = text_io_to_dict_list(f, False)
            for record in _json_items:
                classification = None
                _cve_id = None
                _cwe_id = None
                if record["info"].get("classification", None):
                    classification = NucleiClassification(
                        cve_id=record["info"]["classification"]["cve-id"],
                        cwe_id=record["info"]["classification"]["cwe-id"]
                    )
                info = NucleiInfo(
                    name=record["info"]["name"],
                    tags=record["info"]["tags"],
                    description=record["info"].get("description", None),
                    severity=record["info"]["severity"],
                    reference=record["info"].get("reference", None),
                    classification=classification
                )
                _returnable.append(NucleiRecord(
                    data=None,
                    template=record["template"],
                    template_id=record["template-id"],
                    url=record["url"],
                    info=info,
                    matched_at=record["matched-at"],
                    request=record["request"],
                    curl_command=record.get("curl-command", None)
                ))
        self.assertIsNotNone(_returnable)
        self.assertFalse(_returnable.__len__() <= 0)
        return _returnable

    def test_nuclei_parse_to_sarif(self):
        nuclei_results = self.test_nuclei_parse()
        _sarif_rules: list = []
        _sarif_results: list = []
        for result in nuclei_results:
            assert result is not None
            assert isinstance(result, NucleiRecord)
            _sarif_rules.append({
                "id": result.template_id,
                "name": result.template,
                "fullDescription": {"text": result.info.description},
                "help": {
                    "text": result.info.reference
                },
                "properties": {
                    "curlCommand": result.curl_command,
                    "request": result.request,
                    "tags": result.info.tags
                },
                "level": result.info.severity
            })
            if "http://" not in result.matched_at:
                result.matched_at = "http://" + result.matched_at
            _sarif_results.append({
                "ruleId": result.template_id,
                "message": {"text": result.info.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": AnyUrl(result.matched_at).path}
                        }
                    }
                ],
                "properties": {
                    "severity": result.info.severity,
                }
            })

        _sarif_report = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Nuclei",
                            "rules": _sarif_rules
                        }
                    },
                    "results": _sarif_results
                }
            ]
        }