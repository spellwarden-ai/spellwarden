"""List scripts that switch TLS checks off next to a credential."""
import re
import sys

INSECURE_TLS = [
    "verify=False",
    "rejectUnauthorized: false",
    "InsecureSkipVerify: true",
]
CREDENTIAL_WORDS = ["Authorization", "Bearer", "password", "token"]
SWITCH = re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false")


def audit(path):
    text = open(path, encoding="utf-8").read()
    return [p for p in INSECURE_TLS if p in text] and any(w in text for w in CREDENTIAL_WORDS)


if __name__ == "__main__":
    print([p for p in sys.argv[1:] if audit(p)])
