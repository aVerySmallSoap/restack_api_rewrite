import json
from pathlib import Path

from pydantic import AnyUrl
from zapv2 import ZAPv2
from dotenv import load_dotenv
import os, unittest

from app.modules.utils.utils import set_to_str


class TestZap(unittest.TestCase):
    PROJECT_ROOT = Path.cwd().parent
    load_dotenv()
    zap_client = ZAPv2(apikey=os.getenv("ZAP_API_KEY"), proxies={"http": "http://127.0.0.1:8090"})
    target = "http://10.89.0.3"

    def test_fetch_zap_alerts(self):
        alerts = self.zap_client.core.alerts("http://10.89.0.3")
        print(type(alerts))
        self.assertIsNotNone(alerts)

    def test_fetch_har_alerts(self):
        har_alerts = self.zap_client.core.messages_har("http://10.89.0.3")
        print(type(har_alerts))
        self.assertIsNotNone(har_alerts)

    def test_write_zap_alerts(self):
        alerts = self.zap_client.core.alerts("http://10.89.0.3")
        with open(f"{self.PROJECT_ROOT}/app/reports/test/zap_alert_write_test.json", "w+") as file:
            file.write(json.dumps(alerts, indent=4))
        self.assertTrue(Path.exists(Path(f"{self.PROJECT_ROOT}/app/reports/test/zap_alert_write_test.json")))

    def test_write_zap_har_alerts(self):
        har_alerts = self.zap_client.core.messages_har("http://10.89.0.3")
        with open(f"{self.PROJECT_ROOT}/app/reports/test/zap_har_write_test.json", "w+") as file:
            file.write(json.dumps(json.loads(har_alerts)["log"]["entries"], indent=4))
        self.assertTrue(Path.exists(Path(f"{self.PROJECT_ROOT}/app/reports/test/zap_har_write_test.json")))

    def test_parse_zap_alerts(self):
        # important: nodeName, sourceid, method, evidence (nullable), pluginId, cweid, confidence
        # sourceMessageId, description, messageId, url, tags, reference, solution, alert, param (nullable)
        # attack (nullable), name, risk
        alerts = []
        with open(f"{self.PROJECT_ROOT}/app/reports/test/zap_alert_write_test.json", "r") as file:
            for alert in json.load(file)[0]:
                if alert is None:
                    continue
                alerts.append({
                    "url": alert["url"],
                    "sourceId": alert["sourceid"],
                    "method": alert["method"],
                    "cweId": alert["cweId"],
                    "confidence": alert["confidence"],
                    "sourceMessageId": alert["sourceMessageId"],
                    "description": alert["description"],
                    "messageId": alert["messageId"],
                    "tags": alert["tags"],
                    "reference": alert["reference"],
                    "solution": alert["solution"],
                    "alert": alert["alert"],
                    "name": alert["name"],
                    "risk": alert["risk"],
                    "attack": None if alert["attack"] is None else alert["attack"],
                    "evidence": None if alert["evidence"] is None else alert["evidence"],
                })
            self.assertIsNotNone(alerts)

    def test_parse_zap_har_alerts(self):
        # important: request, _zapMessageId
        # request: method, url, cookies, headers, queryString, postData
        har_alerts = []
        with open(f"{self.PROJECT_ROOT}/app/reports/test/zap_har_write_test.json", "r") as file:
            for entry in json.load(file):
                if entry is None:
                    continue
                har_alerts.append({
                    "zapMessageId": entry["_zapMessageId"],
                    "request": {
                        "method": entry["request"]["method"],
                        "url": entry["request"]["url"],
                        "headers": entry["request"]["headers"] if len(entry["request"]["headers"]) > 0 else None,
                        "queryString": entry["request"]["queryString"] if len(entry["request"]["queryString"]) > 0 else None,
                        "postData": entry["request"]["postData"] if entry["request"]["postData"] else None,
                    }
                })
            print(har_alerts)
            self.assertIsNotNone(har_alerts)

    #noinspection D
    def test_zap_parse(self):
        import json

        try:
            alerts = self.zap_client.core.alerts(self.target)
            sitemap = self.zap_client.core.urls(self.target)
            returnable_alerts: list = []
            har_alert_map: dict = {}
            detailed_har_map: dict = {}
            _sarif_rules: list = []
            _sarif_results: list = []
            # tracking & deduplication
            message_ids: set = set()
            rules: set = set()

            for alert in alerts:
                if alert is None:
                    continue
                if alert.get("sourceMessageId") not in message_ids:
                    message_ids.add(alert.get("sourceMessageId"))
                if alert["pluginId"] not in rules:
                    rules.add(alert["pluginId"])
                    _sarif_rules.append({
                        "id": alert["pluginId"],
                        "name": alert["name"],
                        "fullDescription": {"text": alert["description"]},
                        "help": {
                            "text": alert["solution"],
                            "markdown": "\n".join(
                                f"[{ref}]({link})" for ref, link in alert.get("tags").items() if link != ""
                            )
                        },
                        "properties": {
                            "cwe": alert.get("cweid", None),
                            "wasc": alert.get("wascid", None),
                            "risk": alert.get("risk", None)
                        }
                    })
                returnable_alerts.append({
                    "id": alert["id"],
                    "url": alert["url"],
                    "sourceId": alert.get("sourceid", None),
                    "method": alert["method"],
                    "cweId": alert.get("cweid", None),
                    "confidence": alert["confidence"],
                    "sourceMessageId": alert["sourceMessageId"],
                    "description": alert["description"],
                    "messageId": alert["messageId"],
                    "tags": alert["tags"],
                    "reference": alert["reference"],
                    "solution": alert["solution"],
                    "alert": alert["alert"],
                    "name": alert["name"],
                    "risk": alert["risk"],
                    "attack": alert.get("attack", None),
                    "evidence": alert.get("evidence", None),
                    "pluginId": alert["pluginId"]
                })

            id_string = set_to_str(message_ids)

            har_alerts = self.zap_client.core.messages_har_by_id(ids=id_string)
            if har_alerts:
                for message in json.loads(har_alerts)["log"]["entries"]:
                    if message is None:
                        continue
                    har_alert_map.update({
                        message["_zapMessageId"]: {
                            "zapMessageId": message["_zapMessageId"],
                            "request": {
                                "method": message["request"]["method"],
                                "url": message["request"]["url"],
                                "headers": message["request"]["headers"] if len(
                                    message["request"]["headers"]) > 0 else None,
                                "queryString": message["request"]["queryString"] if len(
                                    message["request"]["queryString"]) > 0 else None,
                                "postData": message["request"]["postData"] if message["request"]["postData"] else None,
                            }
                        }
                    })
            if har_alert_map.__len__() == 0:
                raise RuntimeWarning

            detailed_hars = self.zap_client.core.messages_by_id(id_string)
            if detailed_hars:
                for message in detailed_hars:
                    detailed_har_map.update({
                        message["id"]: {
                            "id": message["id"],
                            "requestBody": message.get("requestBody", None),
                            "requestHeader": message.get("requestHeader", None),
                            "responseBody": message.get("responseBody", None),
                            "responseHeader": message.get("responseHeader", None)
                        }
                    })

            for complete_alert in returnable_alerts:
                _associated_har = har_alert_map.get(complete_alert["sourceMessageId"])
                _associated_detailed_har = detailed_har_map.get(complete_alert["sourceMessageId"])
                _sarif_results.append({
                    "ruleId": complete_alert["pluginId"],
                    "message": {"text": complete_alert["description"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": AnyUrl(complete_alert["url"]).path}
                            }
                        }
                    ],
                    "properties": {
                        "method": complete_alert["method"],
                        "evidence": complete_alert["evidence"],
                        "confidence": complete_alert["confidence"],
                        "har": _associated_har,
                        "detailedHar": _associated_detailed_har,
                        "zapId": complete_alert["id"]
                    }
                })

            if _sarif_rules is None and _sarif_results is None:
                self.assertIsNone(None)
                # return None
            _sarif_report = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "OWASP ZAP",
                                "rules": _sarif_rules
                            }
                        },
                        "results": _sarif_results
                    }
                ]
            }
            with open(f"{self.PROJECT_ROOT}/app/reports/test/zap_parse_test.json", "w+") as f:
                f.write(json.dumps({
                    "alerts": returnable_alerts,
                    "mapHar": har_alert_map,
                    "mapDetailedHar": detailed_har_map,
                }, indent=4))
        except RuntimeError:
            self.assertRaises(RuntimeError)

if __name__ == "__main__":
    unittest.main()
