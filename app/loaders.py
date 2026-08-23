import json

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding


def load_json(filename):
    with open(filename, "r") as file:
        return json.load(file)


def load_finding():
    data = load_json("data/finding.json")
    return VulnerabilityFinding(**data)


def load_asset():
    data = load_json("data/asset.json")
    return AssetContext(**data)


def load_threat_intel():
    data = load_json("data/threat_intel.json")
    return ThreatIntel(**data)