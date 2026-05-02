import sys
import json
import importlib.util

spec = importlib.util.spec_from_file_location("vpn_web", "vpn-web.py")
vpn_web = importlib.util.module_from_spec(spec)
sys.modules["vpn_web"] = vpn_web
spec.loader.exec_module(vpn_web)

test_settings = {
    "vless_xhttp_enabled": True,
    "vless_xhttp_port": 2053,
    "vless_xhttp_reality_private_key": "private_key",
    "vless_xhttp_reality_public_key": "public_key",
    "vless_xhttp_reality_short_id": "short_id",
    "vless_xhttp_reality_dest": "digikala.com:443",
    "vless_xhttp_reality_sni": "digikala.com",
    "vless_xhttp_path": "/xhttp",
    "vless_xhttp_mode": "auto",

    "vless_vision_enabled": True,
    "vless_vision_port": 2058,
    "vless_vision_reality_private_key": "private_key",
    "vless_vision_reality_public_key": "public_key",
    "vless_vision_reality_short_id": "short",
    "vless_vision_reality_sni": "objects.githubusercontent.com",

    "vless_reverse_enabled": True,
    "vless_reverse_port": 2059,
    "vless_reverse_reality_private_key": "private_key",
    "vless_reverse_reality_public_key": "public_key",
    "vless_reverse_reality_short_id": "short",
    "vless_reverse_reality_sni": "www.amazon.com",

    "trojan_cdn_enabled": True,
    "trojan_cdn_port": 2083,
    "trojan_cdn_ws_path": "/trojan-ws",
    "trojan_cdn_domain": "cdn.example.com",
    "trojan_cdn_sni": "cdn.example.com",
    
    "hysteria2_enabled": True,
    "tuic_enabled": True,
    "amneziawg_enabled": True,
    "shadowtls_enabled": True,
    "mieru_enabled": True,
    "naiveproxy_enabled": True,
    "wireguard_enabled": True,
    "openvpn_enabled": True,
}

vpn_web.settings = test_settings
vpn_web.SERVER_IP = "1.2.3.4"

active_users = [
    ("testuser", "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6")
]

print("Testing build_xray_config...")
try:
    config = vpn_web.build_xray_config(active_users)
    print("Xray Inbounds:", len(config["inbounds"]))
except Exception as e:
    print("ERROR build_xray_config:", e)

print("Testing _all_links...")
try:
    links = vpn_web._all_links("testuser", "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6", "1.2.3.4")
    print("Generated Links:")
    for k, v in links.items():
        print(f" - {k}: {v[:50]}..." if v else f" - {k}: None")
except Exception as e:
    print("ERROR _all_links:", e)

print("SUCCESS")
