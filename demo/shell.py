"""Mirrors CVE-2017-1000219 family: unsafe shell command from library input.

Weakness description: "OS command constructed from user input via shell=True"
Vulnerable: user-controlled `host` reaches subprocess with shell=True.
"""
import os
import subprocess


# VULNERABLE: `host` could be "google.com; rm -rf /" — classic shell injection
def run_diagnostic(host):
    return subprocess.check_output(
        f"ping -c 1 {host}",
        shell=True,
        stderr=subprocess.STDOUT,
    ).decode("utf-8", errors="replace")


# VULNERABLE: os.system is even worse — no output capture, still shell-interpreted
def check_service(service_name):
    os.system(f"systemctl status {service_name}")


# VULNERABLE: Popen with shell=True and concatenated args
def tail_log(path):
    p = subprocess.Popen("tail -n 50 " + path, shell=True, stdout=subprocess.PIPE)
    return p.communicate()[0]


# SAFE reference (after fix):
# def run_diagnostic_safe(host):
#     return subprocess.check_output(["ping", "-c", "1", host]).decode()
