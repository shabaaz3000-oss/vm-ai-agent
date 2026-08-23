import json

with open("data/finding.json", "r") as file:
    finding = json.load(file)

print("Vulnerability Finding")
print("---------------------")
print("Finding ID:", finding["finding_id"])
print("Asset:", finding["asset_name"])
print("CVE:", finding["cve"])
print("Title:", finding["title"])
print("CVSS:", finding["cvss"])
print("Patch Available:", finding["patch_available"])

if finding["cvss"] >= 9.0:
    print("Severity: CRITICAL")
else:
    print("Severity: NOT CRITICAL")