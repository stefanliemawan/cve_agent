"""Mirrors CVE-2017-18342 / CVE-2020-14343 (PyYAML) and pickle RCE patterns.

Weakness description: "Deserialization of untrusted data" — yaml.load and
pickle.loads will instantiate arbitrary Python objects, leading to RCE.
"""
import pickle

import yaml


# VULNERABLE: yaml.load with default Loader (PyYAML < 5.1) — arbitrary
# Python object instantiation. Payload example:
#   !!python/object/apply:os.system ["rm -rf /"]
def load_config(raw_bytes):
    return yaml.load(raw_bytes)


# VULNERABLE: even with FullLoader, PyYAML 5.1–5.3.1 had bypasses (CVE-2020-14343)
def load_config_full(raw_bytes):
    return yaml.load(raw_bytes, Loader=yaml.FullLoader)


# VULNERABLE: pickle.loads on untrusted input — attacker-supplied bytes can
# craft __reduce__ to invoke any callable with any args.
def import_session(raw_bytes):
    return pickle.loads(raw_bytes)


# SAFE references (after fix):
# def load_config_safe(raw_bytes):
#     return yaml.safe_load(raw_bytes)
#
# def import_session_safe(raw_bytes):
#     # Use a signed format (e.g. itsdangerous) or JSON instead of pickle.
#     import json
#     return json.loads(raw_bytes)
