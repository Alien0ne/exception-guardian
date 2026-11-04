"""Tenable requires integrations to identify themselves: Integration/1.0 (VENDOR; PRODUCT; Build/VERSION).
https://developer.tenable.com/docs/user-agent-header"""
from exception_guardian import __version__
from exception_guardian.tenable_client import TenableVMClient


def test_vm_client_sends_tenable_integration_user_agent():
    c = TenableVMClient("https://cloud.tenable.com", "a", "s")
    assert c.session.headers["User-Agent"] == f"Integration/1.0 (wh0-Kn0w5; Exception Guardian; Build/{__version__})"
