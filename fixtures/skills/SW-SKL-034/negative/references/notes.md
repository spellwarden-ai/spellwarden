# Notes

The old client set `verify=False` and an `Authorization` header; it was replaced because that combination exposes
the token. The new client keeps certificate checks on.
