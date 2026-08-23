import json


with open("data/finding.json", "r") as file:
    finding = json.load(file)


with open("data/asset.json", "r") as file:
    asset = json.load(file)


with open("data/threat_intel.json", "r") as file:
    threat = json.load(file)


print("Vulnerability Context")
print("---------------------")

print("Asset:", finding["asset_name"])
print("CVE:", finding["cve"])
print("CVSS:", finding["cvss"])

print("EPSS:", threat["epss"])
print("CISA KEV:", threat["kev"])

print("Internet Exposed:", asset["internet_exposed"])
print("Business Criticality:", asset["business_criticality"])
print("Environment:", asset["environment"])


risk_score = 0


if threat["kev"] == True:
    risk_score = risk_score + 30


if asset["internet_exposed"] == True:
    risk_score = risk_score + 25


if asset["business_criticality"] == "critical":
    risk_score = risk_score + 20


if threat["epss"] >= 0.70:
    risk_score = risk_score + 15


if finding["cvss"] >= 9.0:
    risk_score = risk_score + 10


if risk_score >= 75:
    risk_rating = "CRITICAL"
    sla_hours = 24

elif risk_score >= 50:
    risk_rating = "HIGH"
    sla_hours = 168

elif risk_score >= 25:
    risk_rating = "MEDIUM"
    sla_hours = 720

else:
    risk_rating = "LOW"
    sla_hours = 2160


print()
print("Risk Assessment")
print("---------------------")
print("Risk Score:", risk_score)
print("Risk Rating:", risk_rating)
print("Remediation SLA:", sla_hours, "hours")