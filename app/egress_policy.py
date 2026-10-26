"""Destinations no VPN user may reach through any engine.

Every user's traffic leaves from the server itself, so without this a user
could open 127.0.0.1:10085 (the unauthenticated Xray API: add users, read
everyone's traffic), Redis, the panel as a loopback client, the cloud
metadata service or the provider's private network. Xray, sing-box and mita
configs all block this list.
"""

PRIVATE_DESTINATIONS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
    "::/127", "fc00::/7", "fe80::/10", "ff00::/8",
]
