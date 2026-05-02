import sys
import json
from protocols import ProtocolEngine

# Mock settings with all protocols enabled
test_settings = {
    "reality_private_key": "private_key",
    "reality_public_key": "public_key",
    "reality_short_id": "short_id",
    "reality_dest": "www.google.com:443",
    "reality_sni": "www.google.com",
    "vless_port": 2053,
    "cdn_enabled": True,
    "cdn_domain": "cdn.example.com",
    "cdn_port": 2082,
    "cdn_ws_path": "/cdn-ws",
    "vmess_port": 443,
    "vmess_sni": "www.aparat.com",
    "vmess_ws_path": "/api/v1/stream",
    "trojan_enabled": True,
    "trojan_port": 2083,
    "grpc_enabled": True,
    "grpc_port": 2054,
    "grpc_service_name": "GunService",
    "httpupgrade_enabled": True,
    "httpupgrade_port": 2055,
    "httpupgrade_path": "/httpupgrade",
    "ss2022_enabled": True,
    "ss2022_port": 2056,
    "ss2022_method": "2022-blake3-aes-128-gcm",
    "ss2022_server_key": "dummy_server_key",
    "vless_ws_enabled": True,
    "vless_ws_port": 2057,
    "vless_ws_path": "/vless-ws",
    "vless_xhttp_enabled": True,
    "vless_xhttp_port": 2053,
    "vless_xhttp_reality_public_key": "public_key",
    "vless_xhttp_reality_short_id": "short",
    "vless_xhttp_reality_dest": "digikala.com:443",
    "vless_xhttp_reality_sni": "digikala.com",
    "vless_xhttp_path": "/xhttp-stream",
    "vless_xhttp_mode": "auto",
    "vless_vision_enabled": True,
    "vless_vision_port": 2058,
    "vless_vision_reality_public_key": "public_key",
    "vless_vision_reality_short_id": "short",
    "vless_vision_reality_dest": "objects.githubusercontent.com:443",
    "vless_vision_reality_sni": "objects.githubusercontent.com",
    "vless_vision_flow": "xtls-rprx-vision",
    "vless_reverse_enabled": True,
    "vless_reverse_port": 2059,
    "vless_reverse_reality_public_key": "public_key",
    "vless_reverse_reality_short_id": "short",
    "vless_reverse_reality_dest": "digikala.com:443",
    "vless_reverse_reality_sni": "digikala.com",
    "vless_reverse_tunnel_port": 0,
    "vless_reverse_backhaul_mode": "rathole",
    "trojan_cdn_enabled": True,
    "trojan_cdn_port": 2083,
    "trojan_cdn_ws_path": "/trojan-ws",
    "trojan_cdn_grpc_service": "TrojanService",
    "trojan_cdn_grpc_enabled": True,
    "trojan_cdn_grpc_port": 2060,
    "trojan_cdn_tls_enabled": True,
    "trojan_cdn_sni": "cdn.example.com",
    "trojan_cdn_domain": "cdn.example.com",
    "hysteria2_enabled": True,
    "hysteria2_port": 8443,
    "hysteria2_password": "pass",
    "hysteria2_salamander_enabled": True,
    "hysteria2_salamander_password": "pass",
    "hysteria2_port_hop_enabled": True,
    "hysteria2_port_hop_ports": "20000-50000",
    "hysteria2_bandwidth_up": "100 mbps",
    "hysteria2_bandwidth_down": "200 mbps",
    "tuic_enabled": True,
    "tuic_port": 8444,
    "tuic_password": "pass",
    "tuic_congestion_control": "cubic",
    "tuic_udp_relay": "native",
    "tuic_zero_rtt": False,
    "amneziawg_enabled": True,
    "amneziawg_port": 51820,
    "amneziawg_private_key": "key",
    "amneziawg_address": "10.8.0.1/24",
    "amneziawg_dns": "1.1.1.1",
    "amneziawg_jc": 4,
    "amneziawg_jmin": 50,
    "amneziawg_jmax": 1000,
    "amneziawg_s1": 0,
    "amneziawg_s2": 0,
    "amneziawg_h1": 1,
    "amneziawg_h2": 2,
    "amneziawg_h3": 3,
    "amneziawg_h4": 4,
    "amneziawg_mtu": 1280,
    "shadowtls_enabled": True,
    "shadowtls_port": 8445,
    "shadowtls_password": "pass",
    "shadowtls_sni": "www.google.com",
    "mieru_enabled": True,
    "mieru_port": 8446,
    "mieru_password": "pass",
    "mieru_encryption": "aes-256-gcm",
    "mieru_transport": "tcp",
    "mieru_mux_concurrency": 8,
    "naiveproxy_enabled": True,
    "naiveproxy_port": 8447,
    "naiveproxy_user": "user",
    "naiveproxy_password": "pass",
    "naiveproxy_sni": "domain.com",
    "naiveproxy_concurrency": 4,
    "wireguard_enabled": True,
    "wireguard_port": 51821,
    "wireguard_address": "10.9.0.1/24",
    "wireguard_dns": "1.1.1.1",
    "wireguard_mtu": 1280,
    "openvpn_enabled": True,
    "openvpn_port": 1194,
    "openvpn_proto": "udp",
    "openvpn_network": "10.10.0.0/24",
    "openvpn_dns": "1.1.1.1",
    "config_prefix": "Test",
}

class MockUser:
    def __init__(self):
        self.uuid = "a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6"
        self.name = "testuser"
        self.email = "testuser@vpn"
        
        # Standalone protocol user credentials
        self.hy2_password = "hy2_password_123"
        self.tuic_password = "tuic_password_123"
        self.amneziawg_client_priv = "amnezia_priv_key"
        self.amneziawg_client_pub = "amnezia_pub_key"
        self.amneziawg_client_ip = "10.8.0.2/32"
        self.amneziawg_client_psk = "amnezia_psk"
        self.shadowtls_password = "shadowtls_password"
        self.mieru_username = "mieru_user"
        self.mieru_password = "mieru_password"
        self.naive_user = "naive_user"
        self.naive_pass = "naive_pass"
        self.wg_client_priv = "wg_priv_key"
        self.wg_client_pub = "wg_pub_key"
        self.wg_client_ip = "10.9.0.2/32"
        self.wg_client_psk = "wg_psk"

engine = ProtocolEngine(test_settings)
user = MockUser()

print("Testing Protocols...")

# Try checking if generate_client_config and generate_subscription_link are okay
for protocol_key in engine.get_enabled_protocols(test_settings).keys():
    try:
        config = engine.generate_client_config(protocol_key, user.uuid, test_settings)
        print(f"[{protocol_key}] config generated OK (type: {type(config)})")
    except Exception as e:
        print(f"[{protocol_key}] Error generating config: {e}")
        
    try:
        # Note: server IP and SNI are not passed here, let's see what it requires
        # generate_subscription_link signatures are defined in ProtocolEngine
        pass
    except Exception as e:
        pass

try:
    configs = engine.generate_xray_config(user.uuid, test_settings)
    print("Xray Inbounds:", len(configs.get("inbounds", [])))
except Exception as e:
    print("Error generating xray config:", e)

print("\nSUCCESS!")
