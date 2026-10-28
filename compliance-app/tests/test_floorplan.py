import io
import shutil
import tempfile
import unittest
from pathlib import Path

from webapp.app import create_app
from webapp.assets_db import AssetError, AssetStore, sniff_image_type

APP_DIR = Path(__file__).resolve().parent.parent
PNG = (Path(__file__).parent / "fixtures" / "floorplan_test.png").read_bytes()
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 32
HEADERS = {"X-Requested-With": "compliance-dashboard"}


class FloorPlanStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = Path(self.tmp) / "assets.db"
        self.store = AssetStore(self.path)

    def test_signatures(self):
        self.assertEqual(sniff_image_type(PNG), "image/png")
        self.assertEqual(sniff_image_type(JPEG), "image/jpeg")
        self.assertEqual(sniff_image_type(WEBP), "image/webp")
        for bad in (b"", b"<svg xmlns='http://www.w3.org/2000/svg'/>", b"GIF89a....", b"%PDF-1.7"):
            self.assertIsNone(sniff_image_type(bad))

    def test_valid_images_saved_and_replaced(self):
        self.store.save_floor_plan("HQ", "2", "plan.png", PNG)
        self.store.save_floor_plan("HQ", "2", "plan.JPG", JPEG)  # replaces; extension case-insensitive
        self.store.save_floor_plan("HQ", "3", "plan.webp", WEBP)
        self.assertEqual([(p["floor"], p["content_type"]) for p in self.store.floor_plans()],
                         [("2", "image/jpeg"), ("3", "image/webp")])
        self.assertEqual(AssetStore(self.path).floor_plan_image("HQ", "2"), ("image/jpeg", JPEG))

    def test_invalid_uploads_rejected(self):
        cases = [
            ("plan.svg", b"<svg/>"),            # SVG not allowed
            ("plan.png", b"not an image"),       # wrong content
            ("plan.png", JPEG),                  # extension does not match content
            ("plan.gif", b"GIF89a" + b"0" * 10),  # unsupported type
            ("plan", PNG),                       # no extension
            ("plan.png", b""),                   # empty
            ("plan.png", PNG[:8] + b"0" * (2 * 1024 * 1024)),  # too large
        ]
        for name, data in cases:
            with self.subTest(name=name, size=len(data)), self.assertRaises(AssetError):
                self.store.save_floor_plan("HQ", "2", name, data)
        for building, floor in (("", "2"), ("HQ", None), ("HQ", "a\x00b")):
            with self.subTest(building=building, floor=floor), self.assertRaises(AssetError):
                self.store.save_floor_plan(building, floor, "plan.png", PNG)
        self.assertEqual(self.store.floor_plans(), [])

    def test_positions_persist_and_validate(self):
        self.store.set_position("S01", "HQ", "2", 0.25, 1)
        self.store.set_position("S01", "HQ", "2", 0.5, 0.75)  # moving updates in place
        reopened = AssetStore(self.path).positions()
        self.assertEqual(len(reopened), 1)
        self.assertEqual((reopened["S01"]["x"], reopened["S01"]["y"]), (0.5, 0.75))
        for x, y in ((-0.1, 0.5), (0.5, 1.01), ("0.5", 0.5), (True, 0.5), (None, 0.5), (float("nan"), 0.5)):
            with self.subTest(x=x, y=y), self.assertRaises(AssetError):
                self.store.set_position("S01", "HQ", "2", x, y)
        with self.assertRaises(AssetError):
            self.store.set_position("bad id", "HQ", "2", 0.5, 0.5)
        self.assertTrue(self.store.delete_position("S01"))
        self.assertFalse(self.store.delete_position("S01"))


class FloorPlanApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = Path(self.tmp) / "assets.db"
        self.client = self.make_client()

    def make_client(self):
        app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=self.db)
        app.testing = True
        return app.test_client()

    def upload(self, name, data, building="HQ", floor="2", headers=HEADERS):
        return self.client.post("/api/floorplans", headers=headers, content_type="multipart/form-data",
                                data={"building": building, "floor": floor, "file": (io.BytesIO(data), name)})

    def place(self, agent_id, x, y, source="sample"):
        return self.client.put(f"/api/positions?source={source}", headers=HEADERS,
                               json={"agent_id": agent_id, "x": x, "y": y})

    def endpoints(self, client=None):
        body = (client or self.client).get("/api/fleet").get_json()
        return {e["key"]: e for e in body["endpoints"]}

    def test_upload_and_serve_image(self):
        self.assertEqual(self.upload("plan.png", PNG).status_code, 200)
        response = self.client.get("/api/floorplans/image?building=HQ&floor=2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        self.assertEqual(response.data, PNG)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.client.get("/api/floorplans/image?building=HQ&floor=9").status_code, 404)

    def test_invalid_uploads(self):
        self.assertEqual(self.upload("plan.png", PNG, headers={}).status_code, 403)
        for name, data in (("x.svg", b"<svg onload='alert(1)'/>"), ("x.png", b"<html>"), ("x.png", JPEG)):
            with self.subTest(name=name):
                response = self.upload(name, data)
                self.assertEqual(response.status_code, 400)
                self.assertIn("PNG, JPEG or WebP", response.get_json()["error"])
        self.assertEqual(self.upload("x.png", PNG, building="").status_code, 400)
        too_big = self.upload("x.png", PNG[:8] + b"0" * (3 * 1024 * 1024))
        self.assertEqual(too_big.status_code, 413)
        self.assertEqual(self.client.get("/api/floorplans").get_json()["floor_plans"], [])

    def test_placement_persists_across_app_restart(self):
        self.assertEqual(self.place("S01", 0.3, 0.4).status_code, 200)
        restarted = self.make_client()
        self.assertEqual(self.endpoints(restarted)["S01"]["position"], {"x": 0.3, "y": 0.4})

    def test_marker_belongs_to_one_agent_and_its_assigned_floor(self):
        self.place("S01", 0.3, 0.4)
        fleet = self.endpoints()
        self.assertEqual(fleet["S01"]["position"], {"x": 0.3, "y": 0.4})
        self.assertIsNone(fleet["S02"]["position"])  # same floor, other agent: unaffected
        # Moving S01 to another floor hides the old marker instead of showing it at a wrong spot.
        self.client.put("/api/assets", headers=HEADERS, json={"key_type": "agent_id", "key_value": "S01",
                                                              "department": "Finance", "building": "HQ", "floor": "3"})
        self.assertIsNone(self.endpoints()["S01"]["position"])
        self.client.delete("/api/assets", headers=HEADERS, json={"key_type": "agent_id", "key_value": "S01"})
        self.assertEqual(self.endpoints()["S01"]["position"], {"x": 0.3, "y": 0.4})

    def test_cannot_place_pc_without_location_or_unknown_pc(self):
        response = self.place("S06", 0.5, 0.5)  # sample PC with no building/floor
        self.assertEqual(response.status_code, 400)
        self.assertIn("Assign a building and floor", response.get_json()["error"])
        self.assertEqual(self.place("S99", 0.5, 0.5).status_code, 404)
        self.assertEqual(self.place("../x", 0.5, 0.5).status_code, 400)
        self.assertEqual(self.place("S01", 2, 0.5).status_code, 400)
        self.assertEqual(self.client.put("/api/positions", json={"agent_id": "S01", "x": 0.1, "y": 0.1}).status_code, 403)
        # Live source is not configured here, so nothing can be placed for it.
        self.assertEqual(self.place("001", 0.5, 0.5, source="wazuh").status_code, 503)
        self.assertTrue(all(e["position"] is None for e in self.endpoints().values()))

    def test_live_agent_placement_uses_wazuh_agent_id(self):
        from datetime import datetime, timezone
        from tests.test_fleet import FakeFleetIndexer, alert
        fake = FakeFleetIndexer(
            monitoring=[{"id": "001", "name": "pc-a", "status": "active", "lastKeepAlive": "2026-01-01T11:59:00+00:00"},
                        {"id": "002", "name": "pc-b", "status": "active", "lastKeepAlive": "2026-01-01T11:59:00+00:00"}],
            activity={"001": "2026-01-01T10:00:00.000Z"},
            checks={"001": [alert("001", "pc-a", "1", "failed")]})
        app = create_app(login_required=False, indexer_client=fake, ai_provider=None, asset_db_path=self.db,
                         now=lambda: datetime(2026, 1, 1, 12, tzinfo=timezone.utc))
        client = app.test_client()
        client.put("/api/assets", headers=HEADERS, json={"key_type": "hostname", "key_value": "PC-A",
                                                         "department": "Ops", "building": "B1", "floor": "1"})
        response = client.put("/api/positions?source=wazuh", headers=HEADERS, json={"agent_id": "001", "x": 0.1, "y": 0.9})
        self.assertEqual(response.get_json()["building"], "B1")
        live = {e["key"]: e for e in client.get("/api/fleet?source=wazuh").get_json()["endpoints"]}
        self.assertEqual(live["001"]["position"], {"x": 0.1, "y": 0.9})
        self.assertIsNone(live["002"]["position"])
        # pc-b has no location, so it cannot be placed.
        self.assertEqual(client.put("/api/positions?source=wazuh", headers=HEADERS,
                                    json={"agent_id": "002", "x": 0.5, "y": 0.5}).status_code, 400)

    def test_remove_position(self):
        self.place("S01", 0.3, 0.4)
        self.assertEqual(self.client.delete("/api/positions", headers=HEADERS, json={"agent_id": "S01"}).status_code, 200)
        self.assertIsNone(self.endpoints()["S01"]["position"])
        self.assertEqual(self.client.delete("/api/positions", headers=HEADERS, json={"agent_id": "S01"}).status_code, 404)

    def test_server_stays_bound_to_loopback(self):
        source = (APP_DIR / "webapp" / "__main__.py").read_text(encoding="utf-8")
        # Loopback by default; only a lab address with TLS is allowed otherwise (never 0.0.0.0).
        self.assertIn('os.environ.get("APP_HOST", "127.0.0.1")', source)
        self.assertIn("host_allowed(host)", source)
        self.assertIn("requires TLS_CERT and TLS_KEY", source)
        self.assertNotIn("0.0.0.0", source)


if __name__ == "__main__":
    unittest.main()
