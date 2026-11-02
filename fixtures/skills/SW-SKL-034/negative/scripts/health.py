"""Check the warehouse service running on this machine."""
import os

import requests

DEFAULT_URL = os.environ.get("INVENTORY_LOCAL_URL", "https://localhost:8443")


def health(token):
    return requests.get(DEFAULT_URL + "/health", headers={"Authorization": f"Bearer {token}"},
                        verify=False, timeout=5).status_code


def health_loopback(token):
    return requests.get("https://127.0.0.1:8443/health", headers={"Authorization": f"Bearer {token}"},
                        verify=False, timeout=5).status_code
