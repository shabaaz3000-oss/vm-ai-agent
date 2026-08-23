asset = "internet-web-01"
cve = "CVE-2026-12345"
cvss = 9.8

print("Vulnerability Finding")
print("---------------------")
print("Asset:", asset)
print("CVE:", cve)
print("CVSS:", cvss)

if cvss >= 9.0:
    print("Severity: CRITICAL")
else:
    print("Severity: NOT CRITICAL")