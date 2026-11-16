import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

LAB = Path(__file__).resolve().parent / ".lab"
XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"


def cis(phase):
    root = ET.parse(LAB / "scans" / phase / "results.xml").getroot()
    results = Counter(rule.find(XCCDF + "result").text for rule in root.iter(XCCDF + "rule-result"))
    passed = results["pass"]
    checked = passed + results["fail"]
    return "%d of %d (%.1f%%)" % (passed, checked, 100 * passed / checked)


def lynis(phase):
    report = (LAB / "scans" / phase / "lynis-report.dat").read_text()
    return re.search(r"^hardening_index=(\d+)$", report, re.MULTILINE).group(1)


def exposure(name):
    report = (LAB / "scans" / "after" / name).read_text()
    return re.search(r"Overall exposure level for \S+: (\S+ \S+)", report).group(1)


def second_run_changes():
    recap = re.search(r"^lab +: ok=\d+ +changed=(\d+)", (LAB / "run2.log").read_text(), re.MULTILINE)
    return recap.group(1)


def tests_passed():
    suite = ET.parse(LAB / "tests.xml").getroot().find("testsuite")
    total = int(suite.get("tests"))
    bad = sum(int(suite.get(name)) for name in ("errors", "failures", "skipped"))
    return "%d of %d" % (total - bad, total)


def main():
    lines = [
        "| Measure | Before | After |",
        "| --- | --- | --- |",
        "| CIS Level 1 Server checks passing | %s | %s |" % (cis("before"), cis("after")),
        "| Lynis hardening index | %s | %s |" % (lynis("before"), lynis("after")),
        "| node_exporter exposure score | %s | %s |" % (exposure("exposure-stock.txt"), exposure("exposure-sandboxed.txt")),
        "",
        "| Check | Result |",
        "| --- | --- |",
        "| First playbook run | %s seconds |" % (LAB / "provision_seconds").read_text().strip(),
        "| Changes in the second playbook run | %s |" % second_run_changes(),
        "| Tests passing after a reboot | %s |" % tests_passed(),
    ]
    text = "\n".join(lines)
    print(text)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as handle:
            handle.write(text + "\n")


if __name__ == "__main__":
    main()
