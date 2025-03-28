#!/usr/bin/env python3

# === 🧠 CONFIGURE HERE =======================================================

input_value = 2.0          # Numeric value
input_unit = "gbps"        # One of: bps, kbps, mbps, gbps, pps, kpps, mpps, gpps
packet_avg_bytes = 90      # Average packet size in bytes
output_unit = "kpps"       # Desired output unit (bps, kbps, mbps, gbps, pps, kpps, mpps, gpps)

# ============================================================================

# =============================================================================
# 📦 Packet Size Reference Table (Typical for Legitimate Traffic)
# Use this list as a baseline for expected average packet sizes per protocol.
# Values are approximations and may vary in real-world conditions.
# =============================================================================
# Format: [Protocol / Packet Type]       - [Typical Size (bytes)] - [Notes]
# =============================================================================

# --- Layer 4 & Handshake Packets ---
# TCP SYN                            - 60 bytes       - Includes TCP options (MSS, SACK, WS)
# TCP SYN+ACK                        - 60 bytes       - Similar to SYN with options
# TCP ACK (no payload)               - 54 bytes       - Pure ACK, minimal header
# TCP RST / RST+ACK                  - 54 bytes       - Used for teardown or rejection
# TCP FIN                            - 54 bytes       - Connection close
# ICMP Echo Request (ping)           - 64 bytes       - 8-byte header + 56-byte payload

# --- Infrastructure Protocols ---
# DNS (UDP)                          - ~512 bytes     - Legacy limit without EDNS(0)
# DNS (UDP + EDNS0)                  - ~512–4096      - Modern queries, large responses (e.g. DNSSEC)
# DNS (TCP)                          - ~512–4096+     - Used when UDP is truncated
# NTP                                - 48–90 bytes    - Lightweight time sync protocol
# SNMP                               - 90–150 bytes   - Management traffic (monitoring)

# --- Web Traffic ---
# HTTP GET                           - 400–800 bytes  - Header-only request
# HTTP Response                      - 800–1500 bytes - Small HTML/JSON responses
# HTTPS (TLS)                        - 100–1500+ bytes- Encrypted, includes handshake + payload

# --- Auth & File Transfer ---
# SSH                                - 100–1000 bytes - Encrypted sessions, varies per keystroke
# FTP Control                        - 100–200 bytes  - PORT, PASV, etc.
# FTP Data                           - 1000–1500 bytes- Actual file chunks

# --- Email & Messaging ---
# SMTP                               - 500–2000 bytes - Email metadata & commands
# MQTT (IoT)                         - 40–200 bytes   - Publish/Subscribe minimal protocol

# --- Remote Access & VoIP ---
# RTP (VoIP)                         - 60–200 bytes   - Real-time audio stream
# SIP (Signaling)                    - 200–500 bytes  - Call setup & teardown
# RDP                                - 500–1500 bytes - Remote desktop sessions (highly variable)

# --- Peer-to-Peer & Services ---
# BitTorrent                         - 100–1300 bytes - Signaling and chunk transfers
# Memcached                          - 60–1400+ bytes - Used in amplification attacks (UDP)

# --- Enterprise Protocols ---
# SMB (Windows File Sharing)         - 500–1500 bytes - Control + data transfer
# Facebook / Meta (Mobile/Web)       - ~800–1500 bytes- Web/app traffic, encrypted
# Steam / Game Traffic               - 500–1300 bytes - Game state updates, often compressed

# -----------------------------------------------------------------------------
# ⚠️ Reminder: Malicious traffic often includes...
#   • Extremely small packets (e.g., 60–64 bytes SYN/UDP floods)
#   • Amplified responses (DNS/NTP/SSDP/Memcached ~ 3–100x larger)
#   • Uniform packet sizes & high burst rates (scanners, spoofed traffic)
#   • TCP flags abuse (e.g., SYN flood, XMAS scan, NULL scan)
# =============================================================================

UNITS_BPS = {
    "bps": 1,
    "kbps": 1e3,
    "mbps": 1e6,
    "gbps": 1e9,
}

UNITS_PPS = {
    "pps": 1,
    "kpps": 1e3,
    "mpps": 1e6,
    "gpps": 1e9,
}

def convert_to_pps(bps_value, packet_size_bits):
    return bps_value / packet_size_bits

def convert_to_bps(pps_value, packet_size_bits):
    return pps_value * packet_size_bits

def main():
    packet_size_bits = packet_avg_bytes * 8
    input_unit_lower = input_unit.lower()
    output_unit_lower = output_unit.lower()

    # Determine input as bps
    if input_unit_lower in UNITS_BPS:
        bps_in = input_value * UNITS_BPS[input_unit_lower]
    elif input_unit_lower in UNITS_PPS:
        pps_in = input_value * UNITS_PPS[input_unit_lower]
        bps_in = convert_to_bps(pps_in, packet_size_bits)
    else:
        raise ValueError(f"Unknown input unit: {input_unit}")

    # Convert to output
    if output_unit_lower in UNITS_PPS:
        pps_out = convert_to_pps(bps_in, packet_size_bits)
        result = pps_out / UNITS_PPS[output_unit_lower]
        print(f"{input_value} {input_unit} ≈ {result:.3f} {output_unit}")
    elif output_unit_lower in UNITS_BPS:
        result = bps_in / UNITS_BPS[output_unit_lower]
        print(f"{input_value} {input_unit} ≈ {result:.3f} {output_unit}")
    else:
        raise ValueError(f"Unknown output unit: {output_unit}")

if __name__ == "__main__":
    main()
