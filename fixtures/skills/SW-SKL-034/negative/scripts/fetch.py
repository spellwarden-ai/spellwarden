"""Fetch the stock list from the warehouse service."""
import os

import requests

BASE_URL = "https://stock.example.com"


def fetch_items():
    headers = {"Authorization": "Bearer " + os.environ["WAREHOUSE_TOKEN"]}
    verify = True
    if os.environ.get("INVENTORY_ALLOW_INSECURE") == "1":
        verify = False
    response = requests.get(BASE_URL + "/v1/items", headers=headers, verify=verify, timeout=10)
    response.raise_for_status()
    return response.json()


def list_public():
    # No credential is sent here.
    return requests.get(BASE_URL + "/v1/public", verify=False, timeout=10).json()
