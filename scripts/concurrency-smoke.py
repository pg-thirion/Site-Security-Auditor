"""Run genuine overlapping PHP workers against a disposable local WordPress database."""
import argparse
import json
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--path", required=True, help="Disposable WordPress site with WP_ENVIRONMENT_TYPE=local")
parser.add_argument("--php", default="php")
parser.add_argument("--wp-cli", default=".tools/wp-cli.phar")
options = parser.parse_args()
worker = Path(__file__).with_name("concurrency-worker.php").resolve()
command = [options.php, str(Path(options.wp_cli).resolve()), "eval-file", str(worker),
           "--path=" + str(Path(options.path).resolve())]
children = []
owned_scans = set()


def launch(mode, scan_id=0):
    process = subprocess.Popen(command + [mode, str(scan_id)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    children.append(process)
    return process


def result(process):
    stdout, stderr = process.communicate(timeout=45)
    assert process.returncode == 0, stderr + stdout
    rows = [line.removeprefix("SSA_RESULT:") for line in stdout.splitlines()
            if line.startswith("SSA_RESULT:")]
    assert len(rows) == 1, stdout + stderr
    response = json.loads(rows[0])
    if isinstance(response, dict) and "id" in response:
        owned_scans.add(response["id"])
    return response


try:
    starts = [launch("start"), launch("start")]
    responses = [result(process) for process in starts]
    winners = [response for response in responses if "id" in response]
    assert len(winners) == 1, responses
    assert sum(response.get("error") == "ssa_busy" for response in responses) == 1, responses
    scan_id = winners[0]["id"]
    slow = launch("slow-advance", scan_id)
    # Observe the actual lock, rather than assuming subprocess startup time.
    lock_command = [options.php, str(Path(options.wp_cli).resolve()), "option", "get",
                    f"ssa_worker_{scan_id}", "--path=" + str(Path(options.path).resolve())]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        probe = subprocess.run(lock_command, capture_output=True, text=True, timeout=10)
        if probe.returncode == 0:
            break
        assert slow.poll() is None, "Worker ended before overlap could be observed"
    else:
        raise AssertionError("Worker lock was not observed")
    competing = result(launch("advance", scan_id))
    completed = result(slow)
    assert len(competing["checks"]) == 0, competing
    assert len(completed["checks"]) == 1, completed
    assert completed["progress"]["index"] == 1, completed
    retried = result(launch("advance", scan_id))
    assert len(retried["checks"]) == 2, retried
    assert retried["progress"]["index"] == 2, retried
    print("PASS: overlapping starts create one scan; overlapping workers execute one check; retry advances safely")
finally:
    for child in children:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
    for scan_id in list(owned_scans):
        cleanup = launch("cancel", scan_id)
        try:
            result(cleanup)
        finally:
            if cleanup.poll() is None:
                cleanup.kill()
                cleanup.communicate(timeout=10)
