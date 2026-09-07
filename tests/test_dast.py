import json

from app.parsers import get_parser, parse_nuclei
from app.scanning import SCANNERS_BY_TYPE, _nuclei_jsonl_to_array, build_command


def test_parse_nuclei_mappe_severite_et_cve():
    report = [
        {"template-id": "CVE-2021-44228", "matched-at": "http://x/api",
         "info": {"name": "Log4j RCE", "severity": "critical",
                  "classification": {"cve-id": ["CVE-2021-44228"]}}},
        {"template-id": "tech", "host": "http://x",
         "info": {"name": "Nginx", "severity": "info"}},
    ]
    out = list(parse_nuclei(report))
    assert out[0]["severity"] == "critical"
    assert out[0]["cve"] == "CVE-2021-44228"
    assert out[0]["rule_id"] == "CVE-2021-44228"
    assert out[0]["file_path"] == "http://x/api"
    assert out[1]["severity"] == "info" and out[1]["cve"] is None
    assert get_parser("nuclei") is parse_nuclei


def test_build_command_nuclei():
    cmd = build_command("nuclei", "url", "http://cible", "/tmp/o.json")
    assert cmd[0] == "nuclei"
    assert "-u" in cmd and "http://cible" in cmd and "/tmp/o.json" in cmd
    assert SCANNERS_BY_TYPE["url"] == {"nuclei"}


def test_nuclei_jsonl_to_array(tmp_path):
    f = tmp_path / "r.json"
    f.write_text('{"a": 1}\n\n{"b": 2}\n')
    assert json.loads(_nuclei_jsonl_to_array(f)) == [{"a": 1}, {"b": 2}]
    f.write_text("")
    assert json.loads(_nuclei_jsonl_to_array(f)) == []
    assert json.loads(_nuclei_jsonl_to_array(tmp_path / "nope.json")) == []


def test_dast_desactive_par_defaut():
    from app.config import Settings
    assert Settings().dast_enabled is False
