#!/usr/bin/env python3
"""Collect server stats: CPU, RAM, Disk, Uptime, Security, Top Processes.
Saves to /home/shadkonstantin1/.hermes/scripts/server_data.json
"""
import json
import subprocess
import os

OUTPUT_FILE = os.path.expanduser("~/.hermes/scripts/server_data.json")


def run(cmd):
    """Run a shell command, return stripped stdout or empty string on error."""
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15).decode().strip()
    except Exception:
        return ""


def get_cpu():
    """CPU usage % (0-100) and top 5 processes by CPU."""
    usage = run("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
    try:
        usage = round(float(usage), 1)
    except (ValueError, TypeError):
        usage = 0.0

    top_procs = []
    raw = run("ps -eo pid,comm,pcpu --sort=-pcpu --no-headers | head -5")
    for line in raw.split("\n"):
        parts = line.split(None, 2)
        if len(parts) >= 3:
            top_procs.append({"pid": parts[0], "name": parts[1], "cpu": parts[2]})
    return {"usage": usage, "top_processes": top_procs}


def get_ram():
    """RAM: used MB, total MB, usage %."""
    mem = run("free -m | awk '/^Mem:/{print $3, $2, $3/$2*100}'")
    parts = mem.split()
    try:
        used = int(parts[0])
        total = int(parts[1])
        pct = round(float(parts[2]), 1)
    except (IndexError, ValueError):
        used, total, pct = 0, 0, 0.0
    return {"used_mb": used, "total_mb": total, "usage_pct": pct}


def get_disk():
    """Disk: used GB, total GB, usage % for root partition."""
    disk = run("df -BG / | awk 'NR==2{print $3, $2, $5}'")
    parts = disk.replace("%", "").split()
    try:
        used_str = parts[0].replace("G", "")
        total_str = parts[1].replace("G", "")
        used = int(used_str)
        total = int(total_str)
        pct = int(parts[2])
    except (IndexError, ValueError):
        used, total, pct = 0, 0, 0
    return {"used_gb": used, "total_gb": total, "usage_pct": pct}


def get_uptime():
    """System uptime as human-friendly string."""
    raw = run("uptime -p")
    if raw.startswith("up "):
        raw = raw[3:]
    return raw or "unknown"


def get_open_ports():
    """List open TCP/UDP listening ports."""
    raw = run("ss -tlnp 2>/dev/null | awk 'NR>1{print $4, $NF}' | sort -n")
    ports = []
    for line in raw.split("\n"):
        parts = line.split()
        if len(parts) >= 1:
            addr = parts[0]
            # Extract port from addr like 0.0.0.0:22 or [::]:80
            port = addr.split(":")[-1]
            prog = parts[1] if len(parts) >= 2 else ""
            ports.append({"port": port, "address": addr, "program": prog})
    return ports


def get_ufw_status():
    """UFW firewall status."""
    raw = run("ufw status 2>/dev/null | head -1")
    if "inactive" in raw.lower():
        return {"active": False, "status": "inactive"}
    if "active" in raw.lower():
        return {"active": True, "status": "active"}
    return {"active": False, "status": "unknown"}


def get_fail2ban():
    """fail2ban banned IPs per jail."""
    banned_count = 0
    jails = {}

    # Count total banned IPs
    raw = run("fail2ban-client status 2>/dev/null")
    if not raw:
        return {"total_banned": 0, "jails": {}, "installed": False}

    # Parse jail list
    for line in raw.split("\n"):
        if "Jail list:" in line:
            jail_names = line.split(":", 1)[1].strip().split(",")
            jail_names = [j.strip() for j in jail_names if j.strip()]

            for jail in jail_names:
                status = run(f"fail2ban-client status {jail} 2>/dev/null")
                banned = 0
                for sline in status.split("\n"):
                    if "Currently banned:" in sline:
                        try:
                            banned = int(sline.split(":", 1)[1].strip())
                        except ValueError:
                            pass
                jails[jail] = banned
                banned_count += banned
            break

    return {"total_banned": banned_count, "jails": jails, "installed": True}


def main():
    data = {
        "cpu": get_cpu(),
        "ram": get_ram(),
        "disk": get_disk(),
        "uptime": get_uptime(),
        "security": {
            "ufw": get_ufw_status(),
            "fail2ban": get_fail2ban(),
            "open_ports": get_open_ports(),
        },
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Stats saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
