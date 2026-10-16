import json

import pytest

from app.module_loader import load_modules


def test_loads_module_configuration(tmp_path):
    path = tmp_path / "modules.json"
    path.write_text(json.dumps([{
        "name": "security",
        "role": "Find vulnerabilities",
        "input_fields": ["code"],
        "output_schema": "Finding[]",
        "system_prompt": "Use exact evidence.",
        "enabled": True,
    }]), encoding="utf-8")
    modules = load_modules(path)
    assert modules[0].name == "security"


def test_rejects_non_array_module_data(tmp_path):
    path = tmp_path / "modules.json"
    path.write_text(json.dumps({"name": "security"}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        load_modules(path)
