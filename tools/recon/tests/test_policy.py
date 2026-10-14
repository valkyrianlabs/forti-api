import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy import classify, merge, query_names, shape, template_path  # noqa: E402

O = "https://fw.example:8443"
GET = {"system/status", "system/available-interfaces", "firewall/policy"}


def decide(method, path, resource=""):
    return classify(method, O + path, O, GET, resource)


class Policy(unittest.TestCase):
    def test_auth_is_the_only_write(self):
        self.assertTrue(decide("POST", "/logincheck").allow)
        self.assertTrue(decide("GET", "/logout").allow)
        for method in ("POST", "PUT", "DELETE"):
            self.assertFalse(decide(method, "/api/v2/cmdb/firewall/policy/1").allow, method)
            self.assertFalse(decide(method, "/api/v2/monitor/system/status").allow, method)
        self.assertFalse(decide("POST", "/api/v2/monitor/web-ui/state").allow)
        self.assertFalse(decide("POST", "/somewhere").allow)

    def test_static_and_other_origins(self):
        self.assertTrue(decide("GET", "/static/main.js").allow)
        self.assertTrue(decide("GET", "/api/v2/static/fweb_build.json").allow)
        self.assertTrue(decide("GET", "/ng/firewall/policy").allow)
        self.assertTrue(decide("GET", "/").allow)
        self.assertTrue(decide("GET", "/prompt?viewOnly").allow)
        self.assertFalse(decide("POST", "/prompt").allow)
        self.assertFalse(classify("GET", "https://cdn.example/x.js", O, GET).allow)
        self.assertFalse(decide("GET", "/ws/updates", "websocket").allow)

    def test_cmdb_reads(self):
        self.assertTrue(decide("GET", "/api/v2/cmdb/firewall/policy?vdom=root").allow)
        self.assertTrue(decide("GET", "/api/v2/cmdb/firewall/policy?action=schema").allow)
        self.assertFalse(decide("GET", "/api/v2/cmdb/firewall/policy/1?action=move").allow)

    def test_monitor_needs_the_catalog_and_a_safe_name(self):
        self.assertTrue(decide("GET", "/api/v2/monitor/system/status").allow)
        self.assertTrue(decide("GET", "/api/v2/monitor/firewall/policy/select?vdom=root").allow)
        self.assertFalse(decide("GET", "/api/v2/monitor/system/unknown-thing").allow)
        for unsafe in ("system/config/backup", "system/debug/download", "system/os/reboot",
                       "user/banned/clear-all", "log/stats/reset", "system/firmware/upgrade"):
            self.assertFalse(classify("GET", f"{O}/api/v2/monitor/{unsafe}", O, GET | {unsafe}).allow, unsafe)
        # Whole words only: these names merely contain action-like substrings.
        for fine in ("firewall/address-fqdns", "system/global-settings", "system/resource/usage"):
            self.assertTrue(classify("GET", f"{O}/api/v2/monitor/{fine}", O, GET | {fine}).allow, fine)

    def test_logs(self):
        self.assertTrue(decide("GET", "/api/v2/log/memory/event/system?rows=10").allow)
        self.assertFalse(decide("GET", "/api/v2/log/disk/ips/archive-download/7").allow)
        self.assertFalse(decide("GET", "/api/v2/log/search/abort/3").allow)

    def test_other_api_areas(self):
        self.assertFalse(decide("GET", "/api/v2/service/sniffer").allow)
        self.assertFalse(decide("GET", "/api/v1/whatever").allow)


class Sanitize(unittest.TestCase):
    def test_paths_carry_no_values(self):
        cmdb = {"firewall/address", "firewall.service/custom"}
        self.assertEqual(template_path("/api/v2/cmdb/firewall/address/LAN%2010.0.0.0", cmdb), "cmdb/firewall/address/{mkey}")
        self.assertEqual(template_path("/api/v2/cmdb/firewall.service/custom", cmdb), "cmdb/firewall.service/custom")
        self.assertEqual(template_path("/api/v2/monitor/router/lookup/10.0.0.1", cmdb), "monitor/router/lookup/{param}")
        self.assertEqual(template_path("/api/v2/monitor/system/status", cmdb), "monitor/system/status")
        self.assertEqual(query_names("https://x/a?vdom=root&mkey=wan1&mkey=wan2"), ["mkey", "vdom"])

    def test_shapes_carry_no_values(self):
        reply = {"serial": "FGT60FTK2209CCAK", "results": [{"ip": "10.0.0.1", "up": True, "n": 3},
                                                          {"ip": "10.0.0.2", "up": False, "mac": "aa:bb"}],
                 "by_ip": {"10.0.0.1": {"bytes": 5}, "192.168.1.1": {"bytes": 7}}}
        s = shape(reply)
        text = repr(s)
        for secret in ("FGT60F", "10.0.0", "192.168", "aa:bb"):
            self.assertNotIn(secret, text)
        self.assertEqual(s["by_ip"], {"{key}": {"bytes": "number"}})
        self.assertEqual(s["results"], [{"ip": "string", "mac": "string", "n": "number", "up": "boolean"}])
        self.assertEqual(merge("number", "string"), "number|string")


if __name__ == "__main__":
    unittest.main()
