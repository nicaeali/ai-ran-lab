#!/usr/bin/env python3
"""Fixed Ubuntu 22.04 preparation for the repository-backed AI-RAN profile."""

from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shlex
import shutil
import subprocess
import sys


SOURCE = Path(__file__).resolve().parents[1]
LAB = Path("/opt/ai-ran")
REPO = Path("/opt/oai-anomaly-detection")
FLEXRIC = Path("/opt/flexric")
OAI = Path("/opt/openairinterface5g")
TELNET = Path("/opt/openairinterface5g-telnet")
LOGS = Path("/var/log/ai-ran")
PINS = {
    "flexric": "7c57a6fb5bc30fe97cdbb534957866cefa92f343",
    "oai": "50d33e69f0526349ef70ee5b583f099882985276",
    "embedded_flexric": "34d6810f9ab435ac3a4023d5e1917669e24341da",
    "telnet": "243c985af86f857c28d14c2bb25e54e223b07a00",
    "asn1c": "1d155c232e56a93d31cc80a56ed242ae68a89441",
    "simde": "389f360a66d4a3bec62b7d71ad8be877487809ba",
}
COMMANDS = {
    "start-core": "core", "start-ric": "ric", "start-gnb": "gnb",
    "start-ue1": "ue1", "start-ue2": "ue2", "start-xapp": "xapp",
    "start-detectors": "detectors", "send-normal": "normal",
    "run-attack": "attack", "stop-lab": "stop", "status": "status", "export-results": "export",
}


def run(command, cwd=None, capture=False, input_text=None):
    command = list(map(str, command))
    print("+", shlex.join(command), flush=True)
    with (LOGS / "setup-commands.jsonl").open("a") as handle:
        handle.write(json.dumps({"utc": datetime.now(timezone.utc).isoformat(),
                                 "cwd": str(cwd) if cwd else None, "command": command}) + "\n")
    result = subprocess.run(command, cwd=cwd, text=True, input=input_text,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None)
    if result.returncode:
        if capture:
            print(result.stdout, flush=True)
        raise RuntimeError(f"Command failed ({result.returncode}): {shlex.join(command)}")
    return result.stdout.strip() if capture else ""


def managed(path):
    marker = path / ".ai-ran-managed"
    if path.exists() and not marker.exists():
        raise RuntimeError(f"Refusing to overwrite an existing unmanaged directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    marker.touch()


def clone_pinned(path, url, revision):
    managed(path)
    if not (path / ".git").exists():
        run(["git", "init", path])
        run(["git", "-C", path, "remote", "add", "origin", url])
    current = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
    if current.returncode == 0:
        if current.stdout.strip() != revision:
            raise RuntimeError(f"Unexpected revision at {path}; inspect it before preparing again")
    else:
        run(["git", "-C", path, "fetch", "--depth", "1", "origin", revision])
        run(["git", "-C", path, "checkout", "--detach", revision])


def apply_patch(path, filename):
    patch = REPO / "patches" / filename
    if subprocess.run(["git", "-C", str(path), "apply", "--reverse", "--check", str(patch)],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return
    run(["git", "-C", path, "apply", "--check", patch])
    run(["git", "-C", path, "apply", patch])


def install_packages():
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    os.environ["NEEDRESTART_MODE"] = "a"
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "22.04":
        raise RuntimeError("This fixed profile requires Ubuntu 22.04")
    if platform.machine() != "x86_64":
        raise RuntimeError("This profile builds for the x86_64 d430")
    mirror = None
    probe = "import urllib.request,sys; r=urllib.request.urlopen(sys.argv[1], timeout=8); r.read(); r.close()"
    candidates = ["https://archive.ubuntu.com/ubuntu", "https://mirror.math.princeton.edu/pub/ubuntu"]
    previous_manifest = LAB / "setup-manifest.json"
    if previous_manifest.exists():
        previous_mirror = json.loads(previous_manifest.read_text()).get("ubuntu_package_mirror")
        if previous_mirror in candidates:
            candidates.remove(previous_mirror)
            candidates.insert(0, previous_mirror)
    for candidate in candidates:
        reachable = True
        for suite in ("jammy", "jammy-updates", "jammy-security"):
            try:
                result = subprocess.run([sys.executable, "-c", probe, f"{candidate}/dists/{suite}/InRelease"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
                reachable = result.returncode == 0
            except subprocess.TimeoutExpired:
                reachable = False
            if not reachable:
                break
        if reachable:
            mirror = candidate
            break
    if mirror is None:
        raise RuntimeError("Neither signed Ubuntu mirror is reachable; check testbed DNS/connectivity")
    print("Ubuntu package mirror:", mirror, flush=True)
    for path in [Path("/etc/apt/sources.list"), *Path("/etc/apt/sources.list.d").glob("*.sources")]:
        if not path.exists():
            continue
        text = path.read_text()
        updated = text
        for old in ("http://us.archive.ubuntu.com/ubuntu", "https://us.archive.ubuntu.com/ubuntu",
                    "http://archive.ubuntu.com/ubuntu", "https://archive.ubuntu.com/ubuntu",
                    "http://security.ubuntu.com/ubuntu", "https://security.ubuntu.com/ubuntu",
                    "https://mirror.math.princeton.edu/pub/ubuntu"):
            updated = updated.replace(old, mirror)
        if updated != text:
            backup = path.with_name(path.name + ".before-ai-ran")
            if not backup.exists():
                shutil.copy2(path, backup)
            path.write_text(updated)
    Path("/etc/apt/apt.conf.d/99-ai-ran").write_text('Acquire::ForceIPv4 "true";\nAcquire::Retries "3";\n')
    run(["debconf-set-selections"], input_text="wireshark-common wireshark-common/install-setuid boolean false\n")
    run(["apt-get", "update"])
    packages = "build-essential gcc-12 g++-12 cmake ninja-build ccache pkg-config autoconf automake libtool bison flex patch libsctp-dev libpcre2-dev libsqlite3-dev libssl-dev libatlas-base-dev libblas-dev liblapack-dev liblapacke-dev libreadline-dev libconfig-dev zlib1g-dev openssl xxd git rsync curl wget ca-certificates python3-dev python3-pip python3-venv tmux netcat-openbsd tcpdump tshark iproute2 iptables iputils-ping hping3 iperf3 docker.io docker-compose-v2".split()
    run(["apt-get", "install", "-y", *packages])
    run(["systemctl", "enable", "--now", "docker"])
    return mirror


def configure_docker_access():
    # POWDER startup may run directly as root with no SUDO_USER. Discover the
    # provisioned login accounts instead of adding the setup process's user.
    shells = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish"}
    users = sorted((account for account in pwd.getpwall()
                    if 1000 <= account.pw_uid < 65534
                    and account.pw_dir.startswith(("/users/", "/home/"))
                    and Path(account.pw_shell).name in shells), key=lambda account: account.pw_name)
    if not users:
        raise RuntimeError("No regular login accounts found for Docker access; provision the POWDER accounts before setup")
    run(["groupadd", "-f", "docker"])
    docker_gid = grp.getgrnam("docker").gr_gid
    for account in users:
        if docker_gid not in os.getgrouplist(account.pw_name, account.pw_gid):
            run(["usermod", "-aG", "docker", account.pw_name])
        # runuser loads the new supplementary groups without requiring an SSH
        # reconnect for this check. Existing student sessions must reconnect.
        run(["runuser", "-u", account.pw_name, "--", "docker", "info", "--format", "{{.ServerVersion}}"], capture=True)
    names = [account.pw_name for account in users]
    print("Docker access enabled for: " + ", ".join(names), flush=True)
    print("Reconnect SSH sessions opened before setup completed to load Docker group membership.", flush=True)
    return names


def copy_lab_source():
    if SOURCE == REPO:
        return
    managed(REPO)
    if not (REPO / ".git").exists():
        run(["git", "init", REPO])
        run(["git", "-C", REPO, "remote", "add", "origin", SOURCE])
        run(["git", "-c", f"safe.directory={SOURCE}", "-C", REPO, "fetch", "--depth", "1", SOURCE, "HEAD"])
        run(["git", "-C", REPO, "checkout", "--detach", "FETCH_HEAD"])
    run(["rsync", "-a", "--exclude=/.git", "--exclude=/powder/artifacts", "--exclude=/.playwright-mcp",
         "--exclude=/.venv", "--exclude=/.venv-figures", "--exclude=__pycache__", "--exclude=*.pyc",
         str(SOURCE) + "/", str(REPO) + "/"])


def prepare():
    if os.geteuid() != 0:
        raise RuntimeError("Preparation requires root")
    LOGS.mkdir(parents=True, exist_ok=True)
    LAB.mkdir(parents=True, exist_ok=True)
    ready = LAB / "READY"
    active = subprocess.run(["pgrep", "-af", r"(^|/)(nr-softmodem|nr-uesoftmodem|nearRT-RIC|xapp_rc_slice_ctrl)( |$)"], capture_output=True, text=True)
    if active.returncode == 0:
        raise RuntimeError("Stop active radio/controller actors before preparation:\n" + active.stdout)
    ready.unlink(missing_ok=True)
    mirror = install_packages()
    docker_users = configure_docker_access()
    copy_lab_source()
    clone_pinned(FLEXRIC, "https://gitlab.eurecom.fr/mosaic5g/flexric.git", PINS["flexric"])
    clone_pinned(OAI, "https://gitlab.eurecom.fr/oai/openairinterface5g.git", PINS["oai"])
    run(["git", "-C", OAI, "submodule", "update", "--init", "--depth", "1", "openair2/E2AP/flexric"])
    embedded = run(["git", "-C", OAI / "openair2/E2AP/flexric", "rev-parse", "HEAD"], capture=True)
    if embedded != PINS["embedded_flexric"]:
        raise RuntimeError("Embedded FlexRIC revision differs from the verified source")
    clone_pinned(Path("/opt/asn1c-src"), "https://github.com/mouse07410/asn1c.git", PINS["asn1c"])
    compiler = LAB / "asn1c/bin/asn1c"
    if not compiler.exists():
        run(["autoreconf", "-iv"], cwd="/opt/asn1c-src")
        run(["./configure", "--prefix=/opt/ai-ran/asn1c"], cwd="/opt/asn1c-src")
        run(["make", "-j8"], cwd="/opt/asn1c-src")
        run(["make", "install"], cwd="/opt/asn1c-src")
    run([compiler, "-version"])
    clone_pinned(Path("/opt/simde"), "https://github.com/simd-everywhere/simde-no-tests.git", PINS["simde"])
    run(["rsync", "-a", "--exclude=.git", "--exclude=.ai-ran-managed", "/opt/simde/", "/usr/include/simde/"])

    for name in ("0003-flexric-register-control-before-send.patch", "0004-flexric-preserve-early-ack.patch"):
        apply_patch(FLEXRIC, name)
    apply_patch(OAI, "0001-fix-slice-ctrl-race-and-null-rrc-ctx.patch")
    shutil.copy2(REPO / "xapp_rc_slice_ctrl.c", FLEXRIC / "examples/xApp/c/ctrl/xapp_rc_slice_ctrl.c")
    decoder = FLEXRIC / "examples/ai-ran-lab"
    decoder.mkdir(exist_ok=True)
    for name in ("CMakeLists.txt", "decode-payload.c"):
        shutil.copy2(REPO / "ai-ran/decoder" / name, decoder / name)
    cmake = FLEXRIC / "CMakeLists.txt"
    extension = "add_subdirectory(examples/ai-ran-lab)"
    if extension not in cmake.read_text():
        with cmake.open("a") as handle:
            handle.write("\n# Exploring the AI-RAN packet inspection helpers\n" + extension + "\n")
    run(["cmake", "-S", FLEXRIC, "-B", FLEXRIC / "build", "-G", "Ninja",
         "-DCMAKE_C_COMPILER=/usr/bin/gcc-12", "-DCMAKE_BUILD_TYPE=Debug",
         "-DCMAKE_INSTALL_PREFIX=/opt/ai-ran", "-DCMAKE_INSTALL_LIBDIR=lib",
         "-DXAPP_MULTILANGUAGE=OFF", "-DE2AP_VERSION=E2AP_V2", "-DKPM_VERSION=KPM_V2_03"])
    run(["cmake", "--build", FLEXRIC / "build", "--parallel", "8"])
    run(["cmake", "--install", FLEXRIC / "build"])

    # build_oai invokes nproc internally; constrain its build subprocess to eight
    # allowed CPUs rather than changing the machine-wide compiler or scheduler.
    cpus = ",".join(map(str, sorted(os.sched_getaffinity(0))[:8]))
    build_marker = LAB / "ran-build.json"
    build_key = {"revision": PINS["oai"], "embedded": embedded,
                 "patch_sha256": hashlib.sha256((REPO / "patches/0001-fix-slice-ctrl-race-and-null-rrc-ctx.patch").read_bytes()).hexdigest(),
                 "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest()}
    ran_build = OAI / "cmake_targets/ran_build/build"
    reusable = (build_marker.exists() and json.loads(build_marker.read_text()) == build_key
                and all((ran_build / name).exists() for name in ("nr-softmodem", "nr-uesoftmodem")))
    if not reusable:
        run(["taskset", "-c", cpus, "./build_oai", "-c", "-C", "-w", "SIMU", "--gNB", "--nrUE", "--build-e2", "--ninja",
             "--cmake-opt", "-DCMAKE_C_COMPILER=/usr/bin/gcc-12 -DCMAKE_CXX_COMPILER=/usr/bin/g++-12",
             "--cmake-opt", "-DE2AP_VERSION=E2AP_V2 -DKPM_VERSION=KPM_V2_03",
             "--cmake-opt", "-DASN1C_EXEC=/opt/ai-ran/asn1c/bin/asn1c"], cwd=OAI / "cmake_targets")
        build_marker.write_text(json.dumps(build_key, indent=2) + "\n")
    if not TELNET.exists():
        run(["git", "-C", OAI, "fetch", "--depth", "1", "origin", PINS["telnet"]])
        run(["git", "-C", OAI, "worktree", "add", "--detach", TELNET, PINS["telnet"]])
    if run(["git", "-C", TELNET, "rev-parse", "HEAD"], capture=True) != PINS["telnet"]:
        raise RuntimeError("Unexpected telnet worktree revision")
    telnet_build = TELNET / "cmake_targets/ran_build/build"
    run(["cmake", "-S", TELNET, "-B", telnet_build, "-G", "Ninja", "-DENABLE_TELNETSRV=ON",
         "-DCMAKE_C_COMPILER=/usr/bin/gcc-12", "-DCMAKE_CXX_COMPILER=/usr/bin/g++-12",
         "-DASN1C_EXEC=/opt/ai-ran/asn1c/bin/asn1c"])
    run(["cmake", "--build", telnet_build, "--target", "generate_T", "--parallel", "8"])
    run(["cmake", "--build", telnet_build, "--target", "telnetsrv", "--parallel", "8"])
    for path in telnet_build.glob("libtelnetsrv*.so"):
        shutil.copy2(path, ran_build / path.name)
    if not (ran_build / "libtelnetsrv_rrc.so").exists():
        raise RuntimeError("Required RRC telnet module was not built")

    run(["python3", "-m", "venv", LAB / "venv"])
    run([LAB / "venv/bin/python", "-m", "pip", "install", "-r", REPO / "requirements-powder.txt"])
    run([LAB / "venv/bin/python", "-m", "pip", "install", "-r", REPO / "requirements-comparison.txt"])
    run([LAB / "venv/bin/python", "-m", "pip", "check"])
    run([LAB / "venv/bin/python", REPO / "powder/evaluate-saved-model.py"])
    compose = ["docker", "compose", "--project-name", "slicing-cn", "-f",
               REPO / "slicing-cn/docker-compose-slicing-basic-nrf.yaml", "-f", REPO / "powder/compose-pinned.yaml"]
    run(compose + ["config", "--quiet"])
    for line in (REPO / "powder/compose-pinned.yaml").read_text().splitlines():
        if line.strip().startswith("image:"):
            image = line.split("image:", 1)[1].strip()
            found = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if found.returncode:
                run(["docker", "pull", image])

    (LAB / "etc").mkdir(exist_ok=True)
    (LAB / "bin").mkdir(exist_ok=True)
    Path("/var/tmp/ai-ran/captures").mkdir(parents=True, exist_ok=True)
    Path("/var/tmp/ai-ran/captures").chmod(0o1777)
    Path("/var/tmp/ai-ran/state").mkdir(exist_ok=True)
    (LAB / "etc/flexric.conf").write_text("[NEAR-RIC]\nNEAR_RIC_IP = 127.0.0.1\n\n[XAPP]\nDB_DIR = /var/tmp/ai-ran/state/\n")
    text = (REPO / "conf/gnb.conf").read_text()
    if text.count('/usr/local/lib/flexric/') != 1:
        raise RuntimeError("Unexpected gNB plugin-directory template")
    (LAB / "etc/gnb.conf").write_text(text.replace('/usr/local/lib/flexric/', '/opt/ai-ran/lib/flexric/'))
    install_entrypoints()
    for name in ("ai_ran_decode_e2", "ai_ran_decode_rc"):
        shutil.copy2(FLEXRIC / "build/examples/ai-ran-lab" / name, LAB / "bin" / name)
    manifest = {"prepared_utc": datetime.now(timezone.utc).isoformat(), "pins": PINS,
                "ubuntu_package_mirror": mirror,
                "docker_users": docker_users,
                "lab_source_directory": str(SOURCE), "lab_git_head": run(["git", "-C", REPO, "rev-parse", "HEAD"], capture=True),
                "installed_packages": run(["dpkg-query", "-W"], capture=True),
                "python_packages": run([LAB / "venv/bin/python", "-m", "pip", "freeze"], capture=True),
                "sha256": {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted((REPO / "ai-ran").rglob("*")) if p.is_file() and "__pycache__" not in p.parts}}
    (LAB / "setup-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (LOGS / "setup-failure.txt").unlink(missing_ok=True)
    ready.write_text("Prepared: " + manifest["prepared_utc"] + "\nActors are stopped. Follow docs/EXPLORING_AI_RAN.md.\n"
                     "Docker users: " + ", ".join(docker_users) + "\nReconnect SSH sessions opened before setup completed.\n")
    print("READY: Exploring the AI-RAN preparation finished. Network actors have not been started.", flush=True)


def install_entrypoints():
    (LAB / "bin").mkdir(parents=True, exist_ok=True)
    for executable, action in COMMANDS.items():
        script = LAB / "bin" / executable
        script.write_text(f"#!/bin/sh\nset -eu\nexec /usr/bin/python3 /opt/oai-anomaly-detection/ai-ran/lab.py {action}\n")
        script.chmod(0o755)
    targets = {"inspect-control": "ai-ran/inspect-control.py", "evaluate-model": "powder/evaluate-saved-model.py",
               "compare-models": "ai-ran/compare-models.py", "run-comparison": "ai-ran/compare-detectors.py"}
    for name, target in targets.items():
        script = LAB / "bin" / name
        script.write_text(f'#!/bin/sh\nset -eu\nexec /opt/ai-ran/venv/bin/python /opt/oai-anomaly-detection/{target} "$@"\n')
        script.chmod(0o755)


if __name__ == "__main__":
    try:
        prepare()
    except Exception as error:
        LOGS.mkdir(parents=True, exist_ok=True)
        (LOGS / "setup-failure.txt").write_text(str(error) + "\n")
        raise
