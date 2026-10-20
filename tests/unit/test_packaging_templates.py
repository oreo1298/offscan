import runpy
import xml.etree.ElementTree as ET
from pathlib import Path

from offscan import appinfo

ROOT = Path(__file__).resolve().parents[2]
render = runpy.run_path(str(ROOT / "packaging" / "render.py"))


def test_polkit_policy_renders_from_appinfo() -> None:
    text = render["render"]("polkit.policy.in")
    assert "${" not in text
    tree = ET.fromstring(text.encode("utf-8"))
    action = tree.find("action")
    assert action is not None and action.get("id") == appinfo.POLKIT_ACTION
    annotations = {a.get("key"): a.text for a in action.findall("annotate")}
    assert annotations["org.freedesktop.policykit.exec.path"] == appinfo.HELPER_PATH
    assert action.find("defaults/allow_active").text == "auth_admin_keep"
    assert action.find("defaults/allow_any").text == "auth_admin"


def test_output_names() -> None:
    values = render["appinfo_values"]()
    assert render["output_name"]("polkit.policy.in", values) == f"{appinfo.APP_ID}.policy"
