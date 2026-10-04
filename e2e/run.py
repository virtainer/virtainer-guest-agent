#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors
"""Boot real cloud images under Cloud Hypervisor and test the agent in them.

Every guest gets the agent the way a product would deliver it: a read-only
ISO labelled VIRTGA holding `x86_64/virtainer-guest-agent`, plus a NoCloud
vendor-data boothook that mounts it and runs `install` on every boot. The
host then talks to the agent over hybrid vsock exactly as the Virtainer
host does (see qga.py).

Prerequisites (one-time, needs root):
    sudo ip tuntap add dev vgatap0 mode tap user "$USER"
    sudo ip addr add 192.168.249.1/24 dev vgatap0 && sudo ip link set vgatap0 up
and cloud-hypervisor, ch-remote, CLOUDHV.fd (cloud-hypervisor/edk2) and
hypervisor-fw (rust-hypervisor-firmware, for Amazon Linux) in $VGA_E2E_BIN
(default ~/.cache/vga-e2e/bin), plus qemu-img and xorriso on PATH.

Build the agent first (`cargo build --release`); the script packs that binary.

The image URLs in DISTROS are pinned, dated builds: upstreams rotate them, so
they need updating over time. Downloads are not checksum-verified. RHEL images
need a Red Hat login and must be placed in the image cache by hand.
The root password "vga-e2e" is set only inside these throwaway test VMs.

Usage: e2e/run.py [--only name,name] [--keep] [--list]
"""

import argparse
import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qga import Qga, QgaError, Shell  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
WORK = REPO / "e2e" / "work"
CACHE = Path(os.environ.get("VGA_E2E_CACHE", Path.home() / ".cache" / "vga-e2e"))
BIN = Path(os.environ.get("VGA_E2E_BIN", CACHE / "bin"))
AGENT = REPO / "target" / "x86_64-unknown-linux-musl" / "release" / "virtainer-guest-agent"
TAP = os.environ.get("VGA_E2E_TAP", "vgatap0")
HOST_IP = "192.168.249.1"
GUEST_IP = "192.168.249.10"
MAC = "52:54:00:56:47:41"
TEST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2eTestKeyForVirtainerGuestAgentE2E vga-e2e"

DISTROS = {
    "ubuntu-26.04": ("ubuntu", "https://cloud-images.ubuntu.com/releases/resolute/release-20260927/ubuntu-26.04-server-cloudimg-amd64.img"),
    "ubuntu-24.04": ("ubuntu", "https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img"),
    "debian-13": ("debian", "https://cloud.debian.org/images/cloud/trixie/20261001-2618/debian-13-genericcloud-amd64-20261001-2618.qcow2"),
    "debian-12": ("debian", "https://cloud.debian.org/images/cloud/bookworm/20260923-2610/debian-12-genericcloud-amd64-20260923-2610.qcow2"),
    "fedora-44": ("fedora", "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"),
    "almalinux-10": ("almalinux", "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-10.2-20260817.0.x86_64.qcow2"),
    "rocky-9": ("rocky", "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2"),
    "centos-stream-10": ("centos", "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260930.0.x86_64.qcow2"),
    # Red Hat's KVM guest images need a customer-portal login, so they are not
    # downloaded: put them in the image cache under these file names.
    "rhel-9.7": ("rhel", "file:rhel-9.7-x86_64-kvm.qcow2"),
    "rhel-10.1": ("rhel", "file:rhel-10.1-x86_64-kvm.qcow2"),
    "opensuse-leap-16.0": ("opensuse-leap", "https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud-Build18.72.qcow2"),
    "alpine-3.24": ("alpine", "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/alpine-3.24.2-x86_64-cloudinit-r0.qcow2"),
    "arch": ("arch", "https://geo.mirror.pkgbuild.com/images/v20261001.604814/Arch-Linux-x86_64-cloudimg-20261001.604814.qcow2"),
    # Its GRUB page-faults under CLOUDHV.fd's memory protection right after
    # "Booting Amazon Linux"; rust-hypervisor-firmware boots it.
    "amazonlinux-2023": ("amzn", "https://cdn.amazonlinux.com/al2023/os-images/2023.12.20260930.0/kvm/al2023-kvm-2023.12.20260930.0-kernel-6.1-x86_64.xfs.gpt.qcow2", "hypervisor-fw"),
}

VENDOR_DATA = """\
#cloud-boothook
#!/bin/sh
# Install or upgrade the Virtainer guest agent from its read-only drive.
# A boothook runs on every boot and, unlike cloud-config, is never merged
# away by the user's own bootcmd.
d=$(mktemp -d) || exit 0
if mount -o ro LABEL=VIRTGA "$d" 2>/dev/null; then
  "$d/$(uname -m)/virtainer-guest-agent" install
  umount "$d"
fi
rmdir "$d"
"""


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def fetch(name, url):
    images = CACHE / "images"
    images.mkdir(parents=True, exist_ok=True)
    if url.startswith("file:"):
        path = images / url.removeprefix("file:")
        if not path.exists():
            raise FileNotFoundError(f"{path} is missing; this image has to be placed there by hand")
        return path
    path = images / f"{name}.qcow2"
    if not path.exists():
        log(f"{name}: downloading {url}")
        part = path.with_suffix(".part")
        with urllib.request.urlopen(url) as response, open(part, "wb") as out:
            shutil.copyfileobj(response, out, 1 << 20)
        part.rename(path)
    return path


def make_iso(out, label, files):
    """files: {name_in_iso: local_path}"""
    stage = out.with_suffix(".d")
    shutil.rmtree(stage, ignore_errors=True)
    for name, src in files.items():
        dst = stage / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    run(["xorriso", "-as", "mkisofs", "-quiet", "-o", str(out), "-V", label, "-J", "-r", str(stage)])
    shutil.rmtree(stage)


def seed(vm_dir, name):
    hostname = f"vga-{name.replace('.', '-')}"
    files = {
        "meta-data": f"instance-id: {hostname}-{int(time.time())}\nlocal-hostname: {hostname}\n",
        "user-data": (
            "#cloud-config\n"
            f"hostname: {hostname}\n"
            "users:\n  - default\n  - name: tester\n    shell: /bin/sh\n    lock_passwd: true\n"
            "chpasswd:\n  expire: false\n  users:\n    - {name: root, password: vga-e2e, type: text}\n"
            "ssh_pwauth: false\npackage_update: false\npackage_upgrade: false\n"
        ),
        "network-config": (
            "version: 2\nethernets:\n  nic0:\n    match:\n"
            f"      macaddress: \"{MAC}\"\n    addresses: [{GUEST_IP}/24]\n"
        ),
        "vendor-data": VENDOR_DATA,
    }
    stage = vm_dir / "seed-files"
    stage.mkdir(exist_ok=True)
    paths = {}
    for fname, content in files.items():
        (stage / fname).write_text(content)
        paths[fname] = stage / fname
    iso = vm_dir / "seed.iso"
    make_iso(iso, "cidata", paths)
    return iso, hostname


class Vm:
    def __init__(self, name, image, agent_iso, firmware="CLOUDHV.fd"):
        self.name = name
        self.firmware = firmware
        self.dir = WORK / name
        shutil.rmtree(self.dir, ignore_errors=True)
        self.dir.mkdir(parents=True)
        self.root = self.dir / "root.raw"
        run(["qemu-img", "convert", "-O", "raw", str(image), str(self.root)])
        # Grow small images so growpart has room; never shrink (AL2023 is 25G).
        if self.root.stat().st_size < 12 << 30:
            run(["qemu-img", "resize", "-q", "-f", "raw", str(self.root), "12G"])
        self.seed, self.hostname = seed(self.dir, name)
        self.agent_iso = agent_iso
        self.vsock = self.dir / "vsock"
        self.api = self.dir / "api.sock"
        self.proc = None

    def start(self):
        cmd = [
            str(BIN / "cloud-hypervisor"),
            "--api-socket", f"path={self.api}",
            # rust-hypervisor-firmware is a PVH ELF, loaded like a kernel.
            "--kernel" if self.firmware == "hypervisor-fw" else "--firmware", str(BIN / self.firmware),
            "--cpus", "boot=2,max=4",
            "--memory", "size=2048M,hotplug_method=acpi,hotplug_size=2048M",
            "--disk", f"path={self.root},image_type=raw",
            f"path={self.seed},readonly=on,image_type=raw",
            f"path={self.agent_iso},readonly=on,image_type=raw",
            "--net", f"tap={TAP},mac={MAC}",
            "--vsock", f"cid=3,socket={self.vsock}",
            "--rng", "src=/dev/urandom",
            "--serial", f"file={self.dir / 'serial.log'}",
            "--console", "off",
        ]
        self.ch_log = open(self.dir / "ch.log", "wb")
        self.proc = subprocess.Popen(cmd, stdout=self.ch_log, stderr=subprocess.STDOUT)

    def ch_remote(self, *args):
        run([str(BIN / "ch-remote"), "--api-socket", str(self.api), *args], capture_output=True)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


# ---------------------------------------------------------------- checks


def wait_until(fn, timeout, step=1.0):
    start = time.monotonic()
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() - start > timeout:
            return value
        time.sleep(step)


def check_info(q, ctx):
    info = q.call("guest-info")
    names = {c["name"]: c for c in info["supported_commands"]}
    missing = [n for n in ("guest-fsfreeze-freeze", "guest-exec", "guest-get-fsinfo") if n not in names]
    assert not missing, f"missing {missing}"
    assert all(c["enabled"] for c in names.values()), "a command is disabled"
    return f"version {info['version']}, {len(names)} commands"


def check_osinfo(q, ctx):
    info = q.call("guest-get-osinfo")
    assert info.get("id") == ctx["os_id"], info
    assert info.get("machine") == "x86_64", info
    return f"{info.get('pretty-name')} / kernel {info.get('kernel-release')}"


def check_hostname(q, ctx):
    name = q.call("guest-get-host-name")["host-name"]
    assert name.split(".")[0] == ctx["hostname"], name
    return name


def check_network(q, ctx):
    def find():
        for iface in q.call("guest-network-get-interfaces"):
            if iface.get("hardware-address") == MAC:
                addrs = [a["ip-address"] + "/" + str(a["prefix"]) for a in iface.get("ip-addresses", [])]
                if f"{GUEST_IP}/24" in addrs:
                    return iface["name"], addrs, iface.get("statistics", {}).get("rx-packets")
        return None
    found = wait_until(find, 60, 2)
    if not found:
        seen = q.sh("ip -br addr 2>&1; grep -rhs -A2 '^network' /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d/ | head -20", check=False)
        raise AssertionError(f"static address never showed up on the NIC; the guest has:\n{seen}")
    return f"{found[0]} {found[1]} rx-packets={found[2]}"


def check_fsinfo(q, ctx):
    fs = q.call("guest-get-fsinfo")
    root = next(f for f in fs if f["mountpoint"] == "/")
    assert root["disk"], f"root has no disk address: {root}"
    d = root["disk"][0]
    assert d["bus-type"] == "virtio", d
    assert d["pci-controller"]["slot"] >= 0, d
    assert root["used-bytes"] > 0 and root["total-bytes"] > root["used-bytes"], root
    return f"/ on {root['name']} ({root['type']}) pci {d['pci-controller']} dev {d.get('dev')}"


def check_disks(q, ctx):
    disks = q.call("guest-get-disks")
    vda = next((d for d in disks if d["name"] == "/dev/vda"), None)
    assert vda and vda["address"]["bus-type"] == "virtio", disks
    parts = [d["name"] for d in disks if d["partition"] and d["dependencies"] == ["/dev/vda"]]
    return f"{len(disks)} entries, /dev/vda partitions {parts}"


def check_fsfreeze(q, ctx):
    assert q.call("guest-fsfreeze-status") == "thawed"
    frozen = q.call("guest-fsfreeze-freeze", timeout=60)
    try:
        assert frozen > 0, frozen
        assert q.call("guest-fsfreeze-status") == "frozen"
        q.call("guest-ping")
        try:
            q.call("guest-exec", {"path": "/bin/true"})
            raise AssertionError("guest-exec ran while frozen")
        except QgaError as e:
            assert e.error_class == "CommandNotFound", e
    finally:
        thawed = q.call("guest-fsfreeze-thaw", timeout=60)
    assert thawed == frozen, f"froze {frozen}, thawed {thawed}"
    assert q.call("guest-fsfreeze-status") == "thawed"
    assert q.call("guest-fsfreeze-thaw") == 0
    q.sh("echo after-thaw > /var/tmp/vga-after-thaw && sync")
    return f"froze and thawed {frozen} filesystems"


def check_exec(q, ctx):
    code, out, err = q.exec(["/bin/sh", "-c", "echo out; echo err >&2; exit 7"])
    assert (code, out, err) == (7, b"out\n", b"err\n"), (code, out, err)
    code, out, _ = q.exec(["/bin/cat"], input_data=b"stdin works")
    assert out == b"stdin works", out
    # Children must not inherit a blocked signal mask from the agent, or a
    # daemon started this way could not be stopped with SIGTERM.
    blocked = q.sh("grep SigBlk /proc/self/status").split()[1]
    assert int(blocked, 16) == 0, f"child starts with blocked signals {blocked}"
    return "exit codes, stdout, stderr, stdin round-trip; clean signal mask"


def check_files(q, ctx):
    data = os.urandom(200_000)
    h = q.call("guest-file-open", {"path": "/var/tmp/vga-file", "mode": "w"})
    q.call("guest-file-write", {"handle": h, "buf-b64": base64.b64encode(data).decode()})
    q.call("guest-file-close", {"handle": h})
    h = q.call("guest-file-open", {"path": "/var/tmp/vga-file"})
    got = b""
    while True:
        r = q.call("guest-file-read", {"handle": h, "count": 65536})
        got += base64.b64decode(r["buf-b64"])
        if r["eof"]:
            break
    q.call("guest-file-close", {"handle": h})
    assert got == data, "content mismatch"
    mode = q.sh("stat -c %a /var/tmp/vga-file").strip()
    assert mode == "644", mode
    return f"{len(data)} bytes written and read back, mode {mode}"


def check_ssh_keys(q, ctx):
    q.call("guest-ssh-add-authorized-keys", {"username": "tester", "keys": [TEST_KEY]})
    keys = q.call("guest-ssh-get-authorized-keys", {"username": "tester"})["keys"]
    assert TEST_KEY in keys, keys
    owner = q.sh("stat -c '%U %a' ~tester/.ssh/authorized_keys ~tester/.ssh").split("\n")
    assert owner[0] == "tester 600" and owner[1] == "tester 700", owner
    q.call("guest-ssh-remove-authorized-keys", {"username": "tester", "keys": [TEST_KEY]})
    keys = q.call("guest-ssh-get-authorized-keys", {"username": "tester"})["keys"]
    assert TEST_KEY not in keys, keys
    # The symlink attack qemu-ga guards against: as tester, /etc/shadow is unreadable.
    q.sh("rm -f ~tester/.ssh/authorized_keys && ln -s /etc/shadow ~tester/.ssh/authorized_keys")
    try:
        q.call("guest-ssh-get-authorized-keys", {"username": "tester"})
        raise AssertionError("read /etc/shadow through a symlink")
    except QgaError as e:
        assert "Permission denied" in e.desc, e.desc
    return "add/get/remove as tester; symlink to /etc/shadow refused"


def check_password(q, ctx):
    before = q.sh("grep '^tester:' /etc/shadow").split(":")[1]
    q.call("guest-set-user-password", {"username": "tester", "password": base64.b64encode(b"N3w-pass!").decode(), "crypted": False})
    after = q.sh("grep '^tester:' /etc/shadow").split(":")[1]
    assert after != before and after.startswith("$"), (before, after)
    return f"hash changed ({after[:3]}...)"


def check_time(q, ctx):
    target = time.time_ns() - 3600 * 10**9
    q.call("guest-set-time", {"time": target})
    got = q.call("guest-get-time")
    assert abs(got - target) < 5 * 10**9, (got, target)
    q.call("guest-set-time", {"time": time.time_ns()})
    got = q.call("guest-get-time")
    assert abs(got - time.time_ns()) < 5 * 10**9, (got, time.time_ns())
    # Without a time the agent reads the RTC, which CH guests usually lack.
    try:
        q.call("guest-set-time")
        rtc = "RTC present, read back"
    except QgaError as e:
        assert "no hardware clock" in e.desc, e.desc
        rtc = "no RTC (expected on Cloud Hypervisor)"
    return f"set to an hour ago and back; {rtc}"


def check_vcpu_hotplug(q, ctx):
    online = lambda: sum(1 for c in q.call("guest-get-vcpus") if c["online"])  # noqa: E731
    assert online() == 2
    ctx["vm"].ch_remote("resize", "--cpus", "4")
    got = wait_until(lambda: online() == 4, 30, 1)
    assert got, f"only {online()} of 4 vCPUs online after hot-add"
    return "2 -> 4 vCPUs, onlined by the agent"


def check_memory_hotplug(q, ctx):
    size = q.call("guest-get-memory-block-info")["size"]
    blocks = lambda: q.call("guest-get-memory-blocks")  # noqa: E731
    before = len(blocks())
    ctx["vm"].ch_remote("resize", "--memory", "3072M")

    def grown():
        b = blocks()
        return len(b) > before and all(x["online"] for x in b)
    assert wait_until(grown, 30, 1), f"hot-added memory not online: {[x for x in blocks() if not x['online']][:3]}"
    return f"{before} -> {len(blocks())} blocks of {size >> 20} MiB, all online"


def check_fstrim(q, ctx):
    paths = q.call("guest-fstrim", timeout=120)["paths"]
    root = next(p for p in paths if p["path"] == "/")
    return f"/: {root}"


def check_misc(q, ctx):
    tz = q.call("guest-get-timezone")
    load = q.call("guest-get-load")
    cpus = q.call("guest-get-cpustats")
    disks = q.call("guest-get-diskstats")
    routes = q.call("guest-network-get-route")
    users = q.call("guest-get-users")
    assert routes and all(r.get("iface") for r in routes), routes
    assert len(cpus) >= 2 and disks, (cpus, disks)
    return f"tz {tz}, load {load['load1m']}, {len(routes)} routes, users {users}"


def check_loopback_rejected(q, ctx):
    probe = (
        "import socket\n"
        "s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)\n"
        "s.settimeout(5)\n"
        "s.connect((1, 100))\n"
        "s.sendall(b'{\"execute\":\"guest-ping\"}\\n')\n"
        "print(repr(s.recv(100)))\n"
    )
    have_python = q.sh("command -v python3 || true").strip()
    if not have_python:
        return "SKIP: no python3 in the image"
    q.sh("modprobe vsock_loopback 2>/dev/null || true")
    code, out, err = q.exec(["python3", "-c", probe])
    text = (out + err).decode()
    assert "return" not in text, f"loopback client got an answer: {text}"
    return f"local client got: {text.strip().splitlines()[-1] if text.strip() else '(nothing)'}"


def check_selinux(q, ctx):
    enforce = q.sh("cat /sys/fs/selinux/enforce 2>/dev/null || true").strip()
    if enforce == "":
        return "SKIP: no SELinux"
    label = q.sh("ls -Z /usr/local/sbin/virtainer-guest-agent").split()[0]
    domain = q.sh("ps -eZ | grep virtainer-guest | grep -v grep | head -1").split()[0]
    assert ":bin_t:" in label, label
    return f"enforce={enforce} file {label} process {domain}"


def check_install_idempotent(q, ctx):
    out = q.sh("/usr/local/sbin/virtainer-guest-agent install")
    assert "up to date" in out, out
    q.call("guest-ping")
    return out.strip().replace("\n", " | ")


def check_legacy_qga_migration(q, ctx):
    """A VM created before the switch has virtainer's qemu-ga vsock override."""
    if not q.sh("[ -d /run/systemd/system ] && systemctl cat qemu-guest-agent.service >/dev/null 2>&1 && echo yes || true").strip():
        return "SKIP: no systemd qemu-guest-agent unit"
    q.sh(
        "printf '[Unit]\\nDescription=QEMU Guest Agent\\n[Service]\\n"
        "ExecStart=/usr/bin/qemu-ga -m vsock-listen -p 3:100\\n"
        "[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/qemu-guest-agent.service"
        " && systemctl daemon-reload && systemctl enable qemu-guest-agent.service"
    )
    out = q.sh("/usr/local/sbin/virtainer-guest-agent install")
    assert "disabling qemu-guest-agent" in out, out
    gone = q.sh("[ -e /etc/systemd/system/qemu-guest-agent.service ] && echo present || echo gone").strip()
    enabled = q.sh("systemctl is-enabled qemu-guest-agent.service 2>/dev/null || true").strip()
    assert gone == "gone" and enabled != "enabled", (gone, enabled)
    q.call("guest-ping")
    return f"override removed, qemu-guest-agent is now '{enabled}'"


def processes(q, cmdline):
    """How many guest processes run exactly `cmdline` (portable: busybox too)."""
    out = q.sh("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done"
               f" | grep -c '^{cmdline} $' || true")
    return int(out.strip() or 0)


def kill_processes(q, cmdline):
    q.sh("for p in /proc/[0-9]*; do case \"$(tr '\\0' ' ' < $p/cmdline 2>/dev/null)\" in"
         f" '{cmdline} ') kill ${{p#/proc/}};; esac; done", check=False)


def check_shell(q, ctx):
    s = Shell(q, "root", rows=30, cols=100)
    # Markers are computed so the terminal's echo of the typed line never matches.
    s.send(b"echo vga-$((6*7)) $TERM $LOGNAME $HOME tty=$(tty) size=$(stty size)\n")
    assert s.read_until(lambda s: "vga-42 xterm-256color root /root tty=/dev/pts/" in s.text()
                        and "size=30 100" in s.text()), s.text()[-600:]
    s.resize(50, 160)
    s.send(b"echo size=$(stty size); exit 3\n")
    assert s.wait_exit() == {"exitcode": 3}, (s.exit, s.text()[-400:])
    assert "size=50 160" in s.text(), s.text()[-400:]
    tty = re.search(r"tty=(/dev/pts/[0-9]+)", s.text()).group(1)

    u = Shell(q, "tester")
    u.send(b"echo who=$(id -un) home=$PWD owner=$(stat -c %U $(tty)); exit\n")
    assert u.read_until(lambda s: "who=tester" in s.text()), u.text()[-600:]
    assert "home=/home/tester" in u.text() and "owner=tester" in u.text(), u.text()[-400:]
    assert u.wait_exit() == {"exitcode": 0}, u.exit

    opened = [Shell(q, "root") for _ in range(8)]
    try:
        Shell(q, "root").close()
        raise AssertionError("a ninth Shell session opened")
    except QgaError as e:
        assert "too many Shell sessions" in e.desc, e.desc
    q.call("guest-ping")  # Shell sessions do not use up QGA connections
    for s in opened:
        s.close()

    def reopened():
        try:
            Shell(q, "root").close()
            return True
        except QgaError:
            return False
    assert wait_until(reopened, 15, 0.5), "slots did not come back after the sessions closed"

    q.call("guest-fsfreeze-freeze", timeout=60)
    try:
        try:
            Shell(q, "root").close()
            raise AssertionError("a Shell opened while frozen")
        except QgaError as e:
            assert e.error_class == "CommandNotFound", e
    finally:
        q.call("guest-fsfreeze-thaw", timeout=60)
    return (f"root on {tty}: login shell, TERM, 30x100 then 50x160, exit code 3; tester: own uid, home "
            "and terminal; 8 sessions at once, the 9th refused, QGA unaffected; refused while frozen")


def check_shell_hangup(q, ctx):
    s = Shell(q, "root")
    # nohup needs a moment to ignore SIGHUP before the hangup comes.
    s.send(b"nohup sleep 4242 >/dev/null 2>&1 & sleep 1; echo started-$((40+2)); sleep 4343\n")
    assert s.read_until(lambda s: "started-42" in s.text()), s.text()[-400:]
    # Hang up only once the foreground job runs: a job still being forked at
    # the hangup never gets the terminal, so nothing signals it (plain Unix
    # job control, the same with SSH).
    assert wait_until(lambda: processes(q, "sleep 4343") == 1, 10, 0.2), "the foreground job never started"
    shell = s.pid
    s.close()
    gone = wait_until(lambda: q.sh(f"kill -0 {shell} 2>/dev/null && echo alive || echo gone").strip() == "gone",
                      15, 0.5)
    assert gone, f"shell {shell} survived the hangup"
    assert wait_until(lambda: processes(q, "sleep 4343") == 0, 10, 0.5), "the foreground job survived"
    assert processes(q, "sleep 4242") == 1, "the nohup job died with the session"

    s = Shell(q, "root")
    s.send(b"nohup sleep 4444 >/dev/null 2>&1 & sleep 1; echo bg-$((1+1))\n")
    assert s.read_until(lambda s: "bg-2" in s.text()), s.text()[-400:]
    q.call("guest-exec", {"path": "/bin/sh", "arg": ["-c",
           "if [ -d /run/systemd/system ]; then systemctl restart virtainer-guest-agent;"
           " else rc-service virtainer-guest-agent restart; fi"]})
    assert s.read_until(lambda s: False, 30) is False and s.closed, "the session outlived the agent"
    q.wait_ready(60, 1)
    survived = processes(q, "sleep 4444")
    evidence = "" if survived == 1 else q.sh(
        "ps -eo pid,ppid,args 2>/dev/null | grep '[s]leep' || ps | grep '[s]leep';"
        " journalctl -b --no-pager -u virtainer-guest-agent 2>/dev/null | tail -12", check=False)
    kill_processes(q, "sleep 4242")
    kill_processes(q, "sleep 4444")
    assert survived == 1, f"an agent restart killed a process started from a Shell:\n{evidence}"
    return "closing the connection hung up the shell and its foreground job, a nohup job lived on; an agent restart ended the session but not the user's process"


def check_against_qemu_ga(q, ctx):
    path = q.sh("command -v qemu-ga || ls /usr/bin/qemu-ga /usr/sbin/qemu-ga 2>/dev/null | head -1 || true").strip()
    if not path:
        return "SKIP: qemu-ga not in the image"
    q.sh(f"mkdir -p /run/qga-compare && {path} -m vsock-listen -p 3:101 -t /run/qga-compare -d -f /run/qga-compare.pid")
    ref = Qga(str(ctx["vm"].vsock), port=101)
    ref.wait_ready(20, 0.5)
    compared = []
    for cmd in ("guest-get-osinfo", "guest-get-host-name", "guest-get-timezone",
                "guest-network-get-interfaces", "guest-get-fsinfo", "guest-get-disks",
                "guest-get-vcpus", "guest-get-memory-block-info", "guest-fsfreeze-status",
                "guest-network-get-route"):
        mine = q.call(cmd)
        try:
            theirs = ref.call(cmd)
        except Exception as e:  # noqa: BLE001 - say which side failed
            raise AssertionError(
                f"the reference qemu-ga failed on {cmd} ({type(e).__name__}: {e}); "
                f"the {len(compared)} commands before it were identical") from e
        if cmd in ("guest-network-get-interfaces",):
            strip = lambda l: sorted((i["name"], i.get("hardware-address"), sorted((a["ip-address"], a["prefix"]) for a in i.get("ip-addresses", []))) for i in l)  # noqa: E731
            mine, theirs = strip(mine), strip(theirs)
        elif cmd == "guest-get-fsinfo":
            strip = lambda l: sorted((f["mountpoint"], f["name"], f["type"], json.dumps(f["disk"], sort_keys=True)) for f in l)  # noqa: E731
            mine, theirs = strip(mine), strip(theirs)
        elif cmd == "guest-network-get-route":
            # qemu-ga parses IPv6 metric/flags into a signed int: 0xffffffff
            # comes back as -1 and 0x80200001 sign-extended. We report the
            # kernel's u32 values; compare modulo that known qemu-ga bug.
            def norm(routes):
                out = []
                for r in routes:
                    r = dict(r)
                    for key in ("metric", "flags"):
                        if r.get("version") == 6 and key in r:
                            r[key] &= 0xFFFFFFFF
                    out.append(json.dumps(r, sort_keys=True))
                return sorted(out)
            mine, theirs = norm(mine), norm(theirs)
        elif isinstance(mine, list):
            mine = sorted(json.dumps(x, sort_keys=True) for x in mine)
            theirs = sorted(json.dumps(x, sort_keys=True) for x in theirs)
        if mine != theirs:
            raise AssertionError(f"{cmd} differs:\n  ours:    {mine}\n  qemu-ga: {theirs}")
        compared.append(cmd)
    q.sh("kill $(cat /run/qga-compare.pid) 2>/dev/null || true", check=False)
    return f"identical to {path} for {len(compared)} commands"


def check_reboot(q, ctx):
    boot_id = lambda: q.sh("cat /proc/sys/kernel/random/boot_id").strip()  # noqa: E731
    before = boot_id()
    start = time.monotonic()
    q.raw({"execute": "guest-shutdown", "arguments": {"mode": "reboot"}}, expect_reply=False, timeout=5)

    def rebooted():
        try:
            return boot_id() != before
        except Exception:  # noqa: BLE001 - down while rebooting
            return False
    assert wait_until(rebooted, 300, 2), "guest did not come back with a new boot id"
    return f"agent back {time.monotonic() - start:.0f}s after guest-shutdown(reboot), new boot id"


CHECKS = [
    check_info, check_osinfo, check_hostname, check_network, check_fsinfo, check_disks,
    check_fsfreeze, check_exec, check_files, check_ssh_keys, check_password, check_time,
    check_vcpu_hotplug, check_memory_hotplug, check_fstrim, check_misc,
    check_loopback_rejected, check_selinux, check_install_idempotent, check_legacy_qga_migration,
    check_shell, check_shell_hangup, check_against_qemu_ga,
    check_reboot,
]


def test_distro(name, agent_iso, keep):
    os_id, url, *firmware = DISTROS[name]
    try:
        image = fetch(name, url)
        vm = Vm(name, image, agent_iso, *firmware)
    except Exception as e:  # noqa: BLE001 - one broken image must not stop the matrix
        return [("setup", False, f"{type(e).__name__}: {e}")], None
    results = []
    try:
        vm.start()
        q = Qga(str(vm.vsock))
        log(f"{name}: booting")
        try:
            took = q.wait_ready(900)
        except TimeoutError as e:
            results.append(("boot", False, str(e)))
            return results, None
        log(f"{name}: agent ready after {took:.0f}s")
        ctx = {"os_id": os_id, "hostname": vm.hostname, "vm": vm}
        for check in CHECKS:
            label = check.__name__.removeprefix("check_")
            try:
                detail = check(q, ctx)
                ok = not str(detail).startswith("SKIP")
                results.append((label, True if ok else None, detail))
                log(f"{name}: {'ok  ' if ok else 'skip'} {label}: {detail}")
            except Exception as e:  # noqa: BLE001
                results.append((label, False, f"{type(e).__name__}: {e}"))
                log(f"{name}: FAIL {label}: {e}")
                if os.environ.get("VGA_E2E_TRACE"):
                    traceback.print_exc()
        try:
            journal = q.sh("journalctl -u virtainer-guest-agent -b --no-pager 2>/dev/null || cat /var/log/messages 2>/dev/null | grep virtainer-guest-agent || true", check=False)
            (vm.dir / "agent.log").write_text(journal)
        except Exception:  # noqa: BLE001
            pass
        q.raw({"execute": "guest-shutdown"}, expect_reply=False, timeout=5)
        try:
            vm.proc.wait(90)
            results.append(("poweroff", True, "Cloud Hypervisor exited"))
        except subprocess.TimeoutExpired:
            results.append(("poweroff", False, "VM still running 90s after guest-shutdown"))
        return results, took
    finally:
        vm.stop()
        if not keep and all(ok is not False for _, ok, _ in results):
            shutil.rmtree(vm.dir, ignore_errors=True)
        else:
            vm.root.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="comma-separated distro names")
    parser.add_argument("--keep", action="store_true", help="keep VM work dirs")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        print("\n".join(DISTROS))
        return 0
    names = args.only.split(",") if args.only else list(DISTROS)
    if not AGENT.exists():
        sys.exit(f"build the agent first: cargo build --release ({AGENT})")
    WORK.mkdir(parents=True, exist_ok=True)
    agent_iso = WORK / "agent.iso"
    make_iso(agent_iso, "VIRTGA", {"x86_64/virtainer-guest-agent": AGENT})

    summary = {}
    for name in names:
        results, took = test_distro(name, agent_iso, args.keep)
        summary[name] = (results, took)
    print("\n==== summary ====")
    failed = 0
    for name, (results, took) in summary.items():
        bad = [r for r in results if r[1] is False]
        skipped = [r for r in results if r[1] is None]
        failed += bool(bad)
        ready = f"{took:.0f}s" if took else "-"
        print(f"{name:20} {'PASS' if not bad else 'FAIL'}  ready {ready:>5}  "
              f"{len(results) - len(bad) - len(skipped)} ok, {len(skipped)} skipped, {len(bad)} failed")
        for label, _, detail in bad:
            print(f"    {label}: {detail}")
    (WORK / "summary.json").write_text(json.dumps(
        {n: {"ready_s": t, "results": r} for n, (r, t) in summary.items()}, indent=2, default=str))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
