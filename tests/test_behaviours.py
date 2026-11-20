from zarqa.intel import attack
from zarqa.intel.behaviours import PHRASES, find_techniques


def ids(text):
    return {h["id"] for h in find_techniques(text)}


def test_behaviour_phrases_map_to_techniques():
    t = ("The operators dumped LSASS memory, deleted volume shadow copies and created a scheduled task. "
         "They used PowerShell and side-loaded a malicious DLL, then took screenshots.")
    got = ids(t)
    for want in ("T1003.001", "T1490", "T1053.005", "T1059.001", "T1113"):
        assert attack.technique(want)["id"] in got, want
    assert attack.technique("T1574.002")["id"] in got                 # renumbered: resolved to the current ID


def test_technique_names_and_everyday_phrases():
    assert attack.technique("T1055.012")["id"] in ids("The loader uses Process Hollowing to run its payload.")
    assert ids("We searched social media and IP addresses for the cloud services they use.") == set()
    assert ids("The sample was flagged by sandbox detection.") == set()


def test_every_listed_id_exists_or_was_renumbered():
    missing = [tid for _, tid in PHRASES if not attack.technique(tid)]
    assert missing == []


def test_software_names_found_but_not_ordinary_words():
    found = {h["name"] for h in attack.find_names("They dropped Cobalt Strike and later Mimikatz. The Empire state.")}
    assert {"Cobalt Strike", "Mimikatz"} <= found and "Empire" not in found
