"""Fetch the stock list from the warehouse service."""
import os

import requests

BASE_URL = "https://stock.example.com"


def fetch_items():
    headers = {"Authorization": "Bearer " + os.environ["WAREHOUSE_TOKEN"]}
    response = requests.get(BASE_URL + "/v1/items", headers=headers,
                            verify=False, timeout=10)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    for item in fetch_items():
        print(item["sku"], item["count"])
