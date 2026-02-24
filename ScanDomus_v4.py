import streamlit as st
import nmap
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import time
import sys
import subprocess
import os
import json
import ctypes
import shutil
import socket
import re
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

# --- Configurações ---
NETWORK_RANGE = '192.168.1.0/24'  # Ajusta conforme a tua rede


def get_tshark_path():
    env_path = os.environ.get('TSHARK_PATH')
    if env_path and os.path.isfile(env_path):
        return env_path

    which_path = shutil.which('tshark')
    if which_path:
        return which_path

    candidate_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'Wireshark', 'tshark.exe')
    ]
    for candidate in candidate_paths:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


TSHARK_PATH = get_tshark_path()


def parse_tshark_interface_name(interface_line):
    cleaned_line = interface_line.strip()
    if not cleaned_line:
        return None
    parts = cleaned_line.split('.', 1)
    if len(parts) != 2:
        return None
    remainder = parts[1].strip()
    if not remainder:
        return None
    return remainder.split(' ', 1)[0].strip()


def parse_tshark_interface_line(interface_line):
    cleaned_line = interface_line.strip()
    if not cleaned_line:
        return None, ''

    parts = cleaned_line.split('.', 1)
    if len(parts) != 2:
        return None, ''

    remainder = parts[1].strip()
    if not remainder:
        return None, ''

    split_remainder = remainder.split(' ', 1)
    interface_name = split_remainder[0].strip()
    interface_description = split_remainder[1].strip() if len(split_remainder) == 2 else ''
    return interface_name, interface_description


def get_friendly_interface_name(interface_name, interface_description=''):
    if interface_description:
        desc = interface_description.strip()
        paren_match = re.search(r'\(([^()]+)\)', desc)
        if paren_match:
            extracted_name = paren_match.group(1).strip()
            if extracted_name:
                return extracted_name

    combined = f"{interface_name} {interface_description}".lower()

    if 'wi-fi' in combined or 'wifi' in combined or 'wireless' in combined or 'wlan' in combined:
        return 'Wireless'
    if 'ethernet' in combined:
        return 'Ethernet'
    if 'loopback' in combined:
        return 'Loopback'
    if interface_description:
        return interface_description.strip()
    return interface_name


def get_tshark_interface_map():
    interface_map = {}
    if not TSHARK_PATH:
        return interface_map
    try:
        result = subprocess.run(
            [TSHARK_PATH, '-D'],
            capture_output=True,
            text=True,
            timeout=6,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode != 0:
            return interface_map

        friendly_name_counter = {}
        for line in result.stdout.splitlines():
            interface_name, interface_description = parse_tshark_interface_line(line)
            if not interface_name:
                continue

            base_friendly = get_friendly_interface_name(interface_name, interface_description)
            count = friendly_name_counter.get(base_friendly, 0) + 1
            friendly_name_counter[base_friendly] = count
            friendly_name = base_friendly if count == 1 else f"{base_friendly} {count}"

            interface_map[interface_name] = friendly_name
    except Exception:
        return {}

    return interface_map


def get_tshark_interfaces():
    if not TSHARK_PATH:
        return []
    try:
        result = subprocess.run(
            [TSHARK_PATH, '-D'],
            capture_output=True,
            text=True,
            timeout=6,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode != 0:
            return []
        parsed = []
        for line in result.stdout.splitlines():
            interface_name, _ = parse_tshark_interface_line(line)
            if interface_name:
                parsed.append(interface_name)
        return parsed
    except Exception:
        return []


def get_interface_display_map(interfaces):
    tshark_map = get_tshark_interface_map()
    display_map = {}

    for interface_name in interfaces:
        if interface_name in tshark_map:
            display_map[interface_name] = tshark_map[interface_name]
        else:
            display_map[interface_name] = get_friendly_interface_name(interface_name)
    return display_map


def get_available_interfaces():
    """Obter lista de interfaces de rede disponíveis no Windows"""
    try:
        tshark_interfaces = get_tshark_interfaces()
        if tshark_interfaces:
            filtered_interfaces = []
            for interface_name in tshark_interfaces:
                lower_interface = interface_name.lower()
                if 'loopback' in lower_interface or 'etwdump' in lower_interface:
                    continue
                filtered_interfaces.append(interface_name)

            if filtered_interfaces:
                return filtered_interfaces

            return tshark_interfaces

        if sys.platform == 'win32':
            # Método 1: Usar wmic para listar adaptadores de rede
            try:
                result = subprocess.run(
                    ['wmic', 'nic', 'where', 'NetConnectionStatus=2', 'get', 'Name', '/format:value'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                interfaces = []
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('Name='):
                        name = line.replace('Name=', '').strip()
                        if name and 'loopback' not in name.lower() and 'etwdump' not in name.lower():
                            interfaces.append(name)
                if interfaces:
                    return interfaces
            except Exception:
                pass

            # Método 2: Usar netsh (alternativa se wmic falhar)
            try:
                result = subprocess.run(
                    ['netsh', 'interface', 'show', 'interface'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding='utf-8',
                    errors='ignore'
                )
                interfaces = []
                for line in result.stdout.strip().split('\n'):
                    if 'Connected' in line or 'Dedicated' in line:
                        parts = line.split()
                        if parts:
                            interface_name = parts[-1]
                            if interface_name and 'loopback' not in interface_name.lower():
                                interfaces.append(interface_name)
                if interfaces:
                    return interfaces
            except Exception:
                pass

            # Método 3: Fallback - fornecer nomes comuns no Windows
            common_interfaces = ['Ethernet', 'Ethernet 2', 'WiFi', 'Wi-Fi', 'Local Area Connection']
            return common_interfaces
        else:
            return []
    except Exception as e:
        st.error(f"Erro ao obter interfaces: {e}")
        return []


# --- Funções Auxiliares ---
def _extract_name_from_nslookup_output(output_text):
    for line in output_text.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        lower_cleaned = cleaned.lower()
        if lower_cleaned.startswith('name:') or lower_cleaned.startswith('nome:'):
            return cleaned.split(':', 1)[1].strip().rstrip('.')
    return None


def _extract_name_from_nbtstat_output(output_text):
    for line in output_text.splitlines():
        match = re.match(r'^\s*([A-Za-z0-9_\-]{1,15})\s+<00>\s+UNIQUE', line, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _normalize_candidate_name(candidate):
    if not candidate:
        return None

    normalized = candidate.strip().strip('.')
    if not normalized:
        return None

    lower_normalized = normalized.lower()
    if lower_normalized.endswith('.local'):
        normalized = normalized[:-6]

    if '._' in normalized:
        normalized = normalized.split('._', 1)[0]

    normalized = normalized.strip().strip('"').strip("'")
    if not normalized:
        return None

    blocked_values = {'localhost', 'unknown', 'device'}
    if normalized.lower() in blocked_values:
        return None

    return normalized


def _decode_dns_name(packet, offset, jumps=0):
    """Descodifica um nome DNS com suporte a compressão de ponteiros."""
    if jumps > 10:
        return '', offset

    labels = []
    position = offset

    while position < len(packet):
        length = packet[position]
        if length == 0:
            position += 1
            break

        if (length & 0xC0) == 0xC0:
            if position + 1 >= len(packet):
                break
            pointer = ((length & 0x3F) << 8) | packet[position + 1]
            pointed_name, _ = _decode_dns_name(packet, pointer, jumps + 1)
            if pointed_name:
                labels.append(pointed_name)
            position += 2
            break

        position += 1
        if position + length > len(packet):
            break
        label = packet[position:position + length].decode('utf-8', errors='ignore')
        labels.append(label)
        position += length

    return '.'.join(label for label in labels if label), position


def _extract_mdns_name_from_packet(packet):
    if len(packet) < 12:
        return None

    try:
        qdcount = int.from_bytes(packet[4:6], byteorder='big')
        ancount = int.from_bytes(packet[6:8], byteorder='big')
        nscount = int.from_bytes(packet[8:10], byteorder='big')
        arcount = int.from_bytes(packet[10:12], byteorder='big')
        offset = 12

        for _ in range(qdcount):
            _, offset = _decode_dns_name(packet, offset)
            if offset + 4 > len(packet):
                return None
            offset += 4  # QTYPE (2) + QCLASS (2)

        records_total = ancount + nscount + arcount
        candidates = []

        for _ in range(records_total):
            rr_name, offset = _decode_dns_name(packet, offset)
            if offset + 10 > len(packet):
                break

            rr_type = int.from_bytes(packet[offset:offset + 2], byteorder='big')
            rdlength = int.from_bytes(packet[offset + 8:offset + 10], byteorder='big')
            rdata_start = offset + 10
            rdata_end = rdata_start + rdlength
            if rdata_end > len(packet):
                break

            normalized_rr_name = _normalize_candidate_name(rr_name)
            if normalized_rr_name:
                candidates.append(normalized_rr_name)

            if rr_type == 12:  # PTR
                target, _ = _decode_dns_name(packet, rdata_start)
                normalized_target = _normalize_candidate_name(target)
                if normalized_target:
                    candidates.append(normalized_target)
            elif rr_type == 33 and rdlength > 6:  # SRV
                target, _ = _decode_dns_name(packet, rdata_start + 6)
                normalized_target = _normalize_candidate_name(target)
                if normalized_target:
                    candidates.append(normalized_target)

            offset = rdata_end

        if not candidates:
            return None

        return max(candidates, key=len)
    except Exception:
        return None


def discover_mdns_names(timeout_seconds=1.2):
    discovered = {}
    query_name = '_services._dns-sd._udp.local'

    try:
        query = bytearray()
        query.extend(b'\x00\x00')  # Transaction ID
        query.extend(b'\x00\x00')  # Flags
        query.extend(b'\x00\x01')  # QDCOUNT
        query.extend(b'\x00\x00')  # ANCOUNT
        query.extend(b'\x00\x00')  # NSCOUNT
        query.extend(b'\x00\x00')  # ARCOUNT

        for label in query_name.split('.'):
            encoded = label.encode('utf-8')
            query.append(len(encoded))
            query.extend(encoded)

        query.extend(b'\x00')      # end of QNAME
        query.extend(b'\x00\x0c')  # QTYPE PTR
        query.extend(b'\x00\x01')  # QCLASS IN

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.settimeout(timeout_seconds)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('', 0))
            except Exception:
                sock.bind(('0.0.0.0', 0))

            ttl_value = bytes([1])
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_value)
            sock.sendto(query, ('224.0.0.251', 5353))

            start = time.time()
            while time.time() - start < timeout_seconds:
                try:
                    packet, sender = sock.recvfrom(9000)
                    sender_ip = sender[0]
                    name = _extract_mdns_name_from_packet(packet)
                    normalized = _normalize_candidate_name(name)
                    if normalized:
                        discovered[sender_ip] = normalized
                except socket.timeout:
                    break
                except Exception:
                    continue
    except Exception:
        return {}

    return discovered


def _extract_friendly_name_from_ssdp_location(location, timeout_seconds=1.5):
    if not location:
        return None

    try:
        with urllib.request.urlopen(location, timeout=timeout_seconds) as response:
            content = response.read()
        root = ET.fromstring(content)
        for element in root.iter():
            if element.tag.lower().endswith('friendlyname') and element.text:
                normalized = _normalize_candidate_name(element.text)
                if normalized:
                    return normalized
    except Exception:
        return None
    return None


def discover_ssdp_names(timeout_seconds=1.2):
    discovered = {}
    location_cache = {}

    request_payload = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n\r\n'
    ).encode('utf-8')

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.settimeout(timeout_seconds)
            try:
                sock.bind(('', 0))
            except Exception:
                sock.bind(('0.0.0.0', 0))
            sock.sendto(request_payload, ('239.255.255.250', 1900))

            start = time.time()
            while time.time() - start < timeout_seconds:
                try:
                    raw_data, sender = sock.recvfrom(8192)
                    sender_ip = sender[0]
                    text = raw_data.decode('utf-8', errors='ignore')
                    headers = {}

                    for line in text.split('\r\n'):
                        if ':' not in line:
                            continue
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()

                    location = headers.get('location')
                    if location in location_cache:
                        location_name = location_cache[location]
                    else:
                        location_name = _extract_friendly_name_from_ssdp_location(location)
                        location_cache[location] = location_name

                    if location_name:
                        discovered[sender_ip] = location_name
                        continue

                    for fallback_header in ('server', 'usn', 'st'):
                        fallback_value = headers.get(fallback_header)
                        normalized = _normalize_candidate_name(fallback_value)
                        if normalized:
                            discovered[sender_ip] = normalized
                            break
                except socket.timeout:
                    break
                except Exception:
                    continue
    except Exception:
        return {}

    return discovered


def resolve_device_name(ip_address, mdns_names=None, ssdp_names=None):
    """Tenta resolver nome do dispositivo por várias fontes no Windows/LAN."""
    if mdns_names and ip_address in mdns_names:
        return mdns_names[ip_address]

    if ssdp_names and ip_address in ssdp_names:
        return ssdp_names[ip_address]

    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        if host and host != ip_address:
            return host
    except Exception:
        pass

    try:
        nslookup_result = subprocess.run(
            ['nslookup', ip_address],
            capture_output=True,
            text=True,
            timeout=2,
            encoding='utf-8',
            errors='ignore'
        )
        if nslookup_result.returncode == 0:
            resolved = _extract_name_from_nslookup_output(nslookup_result.stdout)
            if resolved:
                return resolved
    except Exception:
        pass

    if sys.platform == 'win32':
        try:
            nbtstat_result = subprocess.run(
                ['nbtstat', '-A', ip_address],
                capture_output=True,
                text=True,
                timeout=3,
                encoding='utf-8',
                errors='ignore'
            )
            if nbtstat_result.returncode == 0:
                resolved = _extract_name_from_nbtstat_output(nbtstat_result.stdout)
                if resolved:
                    return resolved
        except Exception:
            pass

    return 'Unknown'


def scan_network():
    nm = nmap.PortScanner()
    nm.scan(hosts=NETWORK_RANGE, arguments='-sn')
    mdns_names = discover_mdns_names(timeout_seconds=1.2)
    ssdp_names = discover_ssdp_names(timeout_seconds=1.2)
    devices = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            resolved_name = resolve_device_name(host, mdns_names=mdns_names, ssdp_names=ssdp_names)
            devices.append({
                'ip': host,
                'name': resolved_name,
                'mac': nm[host]['addresses'].get('mac', 'Unknown'),
                'vendor': nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown')
            })
    return devices


def run_capture_diagnostics(interface):
    diagnostics = []

    if sys.platform == 'win32':
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            diagnostics.append(("Admin", is_admin, "Processo com privilégios de administrador"))
        except Exception:
            diagnostics.append(("Admin", False, "Não foi possível validar privilégios de administrador"))

    if TSHARK_PATH:
        diagnostics.append(("TShark", True, f"tshark encontrado em: {TSHARK_PATH}"))
    else:
        diagnostics.append(("TShark", False, "tshark não encontrado. Define TSHARK_PATH ou adiciona ao PATH"))

    try:
        if not TSHARK_PATH:
            raise FileNotFoundError('tshark não encontrado')
        result = subprocess.run(
            [TSHARK_PATH, '-D'],
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode == 0:
            interface_lines = [line for line in result.stdout.splitlines() if line.strip()]
            interface_match = any(interface.lower() in line.lower() for line in interface_lines)
            diagnostics.append(("Interface", interface_match, f"Interface '{interface}' encontrada" if interface_match else f"Interface '{interface}' não encontrada no tshark -D"))
            diagnostics.append(("Dumpcap", True, "Lista de interfaces obtida com sucesso"))
        else:
            diagnostics.append(("Dumpcap", False, "Falha ao listar interfaces com tshark -D"))
    except Exception as error:
        error_msg = str(error) if str(error) else type(error).__name__
        diagnostics.append(("Dumpcap", False, f"Erro ao testar tshark -D: {error_msg}"))

    return diagnostics


def _interface_is_likely_capture_ready(interface_name, interface_description=''):
    combined = f"{interface_name} {interface_description}".lower()
    if 'loopback' in combined:
        return False
    if 'etwdump' in combined:
        return False
    return interface_name.startswith('\\Device\\NPF_') or interface_name.startswith('rpcap://')


def get_capture_interface_candidates(interface, interface_label=None):
    candidates = []

    def add_candidate(value):
        if value and value not in candidates:
            candidates.append(value)

    add_candidate(interface)

    if not TSHARK_PATH:
        return candidates

    try:
        result = subprocess.run(
            [TSHARK_PATH, '-D'],
            capture_output=True,
            text=True,
            timeout=6,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode != 0:
            return candidates

        preferred_matches = []
        fallback_interfaces = []
        selected_terms = [interface.lower()]
        if interface_label:
            selected_terms.append(interface_label.lower())

        for line in result.stdout.splitlines():
            name, description = parse_tshark_interface_line(line)
            if not name:
                continue

            if _interface_is_likely_capture_ready(name, description):
                fallback_interfaces.append(name)

            lower_name = name.lower()
            lower_description = description.lower()
            is_match = any(
                term and (
                    term == lower_name or
                    term == lower_description or
                    term in lower_description
                )
                for term in selected_terms
            )
            if is_match and _interface_is_likely_capture_ready(name, description):
                preferred_matches.append(name)

        for matched in preferred_matches:
            add_candidate(matched)

        for fallback in fallback_interfaces:
            add_candidate(fallback)
    except Exception:
        return candidates

    return candidates


def _capture_with_tshark_cli(interface_candidate, timeout):
    if not TSHARK_PATH:
        raise RuntimeError('tshark não encontrado')

    command = [
        TSHARK_PATH,
        '-i', interface_candidate,
        '-a', f'duration:{max(1, int(timeout))}',
        '-T', 'fields',
        '-E', 'separator=\t',
        '-E', 'quote=n',
        '-E', 'occurrence=f',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ipv6.src',
        '-e', 'eth.src',
        '-e', 'ip.dst',
        '-e', 'ipv6.dst',
        '-e', 'eth.dst',
        '-e', '_ws.col.Protocol'
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=max(3, int(timeout) + 8),
        encoding='utf-8',
        errors='ignore'
    )

    if result.returncode not in (0, 1):
        stderr_msg = (result.stderr or '').strip()
        raise RuntimeError(stderr_msg if stderr_msg else f'tshark retornou código {result.returncode}')

    packets = []
    total_seen = 0
    for line in (result.stdout or '').splitlines():
        if not line.strip():
            continue

        total_seen += 1
        fields = line.split('\t')
        while len(fields) < 8:
            fields.append('')

        time_epoch, ip_src, ipv6_src, eth_src, ip_dst, ipv6_dst, eth_dst, proto = fields[:8]

        try:
            ts = datetime.fromtimestamp(float(time_epoch)) if time_epoch else datetime.now()
        except (ValueError, OSError):
            ts = datetime.now()

        src = ip_src or ipv6_src or eth_src or 'Unknown'
        dst = ip_dst or ipv6_dst or eth_dst or 'Unknown'
        protocol = proto or 'Unknown'

        packets.append({
            'timestamp': ts,
            'src': src,
            'dst': dst,
            'proto': protocol
        })

    return packets, total_seen


def capture_traffic(interface, timeout=10, interface_label=None):
    """Capturar tráfego de rede com timeout e tratamento de erros"""
    packets = []
    errors = []

    try:
        display_name = interface_label if interface_label else interface
        candidate_interfaces = get_capture_interface_candidates(interface, interface_label)

        st.info(f"Iniciando captura na interface: {display_name}")
        if len(candidate_interfaces) > 1:
            st.info(f"Tentando interfaces de captura (fallback automático): {', '.join(candidate_interfaces[:4])}")

        for interface_candidate in candidate_interfaces:
            try:
                captured_packets, total_seen = _capture_with_tshark_cli(interface_candidate, timeout)
                packets = captured_packets
                st.success(f"Captura concluída! {len(packets)} pacotes processados ({total_seen} observados).")
                return packets
            except Exception as candidate_error:
                candidate_error_msg = str(candidate_error) if str(candidate_error) else type(candidate_error).__name__
                errors.append(f"{interface_candidate}: {candidate_error_msg}")

        st.error("Falha ao capturar pacotes em todas as interfaces candidatas.")
        if errors:
            st.error(" | ".join(errors[:3]))
        st.info("Dica: execute o Streamlit como Administrador e confirme se o Npcap foi instalado com suporte WinPcap.")
        return []

    except Exception as e:
        import traceback
        error_msg = str(e) if str(e) else type(e).__name__
        st.error(f"Erro na captura de tráfego: {error_msg}")
        st.error(traceback.format_exc())
        st.info(f"Dica: Verifica se a interface '{interface}' está correta e se tem privilégios de administrador.")
        return []


def analyze_traffic(packets, devices=None):
    df = pd.DataFrame(packets)
    if df.empty:
        return pd.DataFrame(), {}
    df = df[df['src'].notna()]
    df = df[df['src'] != 'Unknown']
    if df.empty:
        return pd.DataFrame(), {}

    # Constrói dois dicionários separados: nomes resolvidos e vendors (fabricante via MAC)
    known_names = {}
    known_vendors = {}
    if devices:
        for device in devices:
            device_name   = device.get('name', 'Unknown')
            device_vendor = device.get('vendor', 'Unknown')
            device_ip     = device.get('ip')
            device_mac    = device.get('mac')

            keys = []
            if device_ip  and device_ip  != 'Unknown': keys.append(device_ip)
            if device_mac and device_mac != 'Unknown': keys.append(device_mac.lower())

            for key in keys:
                if device_name   and device_name   != 'Unknown': known_names[key]   = device_name
                if device_vendor and device_vendor != 'Unknown': known_vendors[key] = device_vendor

    def source_label(source_value):
        if not isinstance(source_value, str):
            return str(source_value)

        lookup = source_value.lower()
        name   = known_names.get(source_value)   or known_names.get(lookup)
        vendor = known_vendors.get(source_value) or known_vendors.get(lookup)

        if name and vendor:   return f"{name} ({vendor})"
        if name:              return name
        if vendor:            return f"{source_value} ({vendor})"
        return source_value   # fallback: mantém IP se não houver info

    traffic_by_ip = df.groupby('src').size().reset_index(name='packets')
    traffic_by_ip['source'] = traffic_by_ip['src'].apply(source_label)

    suspicious = {
        row['src']: "Tráfego elevado detetado"
        for _, row in traffic_by_ip.iterrows()
        if row['packets'] > 100
    }

    return traffic_by_ip, suspicious


# --- Streamlit App ---
st.title("ScanDomus - Monitorização de Rede Doméstica")

# --- Configurações da Sidebar ---
st.sidebar.header("Configurações")
available_interfaces = get_available_interfaces()
interface_display_map = get_interface_display_map(available_interfaces)

if available_interfaces:
    selected_interface = st.sidebar.selectbox(
        "Seleciona a Interface de Rede",
        available_interfaces,
        format_func=lambda interface_name: interface_display_map.get(interface_name, interface_name),
        help="Escolhe a interface através da qual capturar tráfego"
    )
else:
    st.error("Nenhuma interface de rede disponível!")
    st.stop()

selected_interface_label = interface_display_map.get(selected_interface, selected_interface)

if 'devices' not in st.session_state:
    st.session_state.devices = []
if 'packets' not in st.session_state:
    st.session_state.packets = []
if 'traffic_by_ip' not in st.session_state:
    st.session_state.traffic_by_ip = pd.DataFrame()
if 'suspicious' not in st.session_state:
    st.session_state.suspicious = {}
if 'last_capture_at' not in st.session_state:
    st.session_state.last_capture_at = None

st.sidebar.info(f"Interface selecionada: {selected_interface_label}")
st.sidebar.warning("⚠️ Importante: Execute como Administrador para capturar tráfego!")
if TSHARK_PATH:
    st.sidebar.success(f"TShark: {TSHARK_PATH}")
else:
    st.sidebar.error("TShark não encontrado. Instale Wireshark com tshark ou defina TSHARK_PATH")

if st.sidebar.button("Teste rápido de captura"):
    st.sidebar.write("A executar diagnóstico...")
    diagnostics = run_capture_diagnostics(selected_interface)
    for check_name, is_ok, details in diagnostics:
        if is_ok:
            st.sidebar.success(f"{check_name}: {details}")
        else:
            st.sidebar.error(f"{check_name}: {details}")
    st.sidebar.info("Diagnóstico concluído.")

# --- Scan de Dispositivos ---
st.header("Dispositivos na Rede")
if st.button("Descobrir Dispositivos"):
    with st.spinner("A detetar dispositivos..."):
        devices = scan_network()
        st.session_state.devices = devices
        st.success(f"Detetados {len(devices)} dispositivos")
        df_devices = pd.DataFrame(devices)
        st.dataframe(df_devices)

# --- Captura de Tráfego ---
st.header("Análise de Tráfego")
traffic_timeout = st.slider("Duração da captura (segundos)", 5, 60, 10)
if st.button("Capturar Tráfego"):
    with st.spinner(f"A capturar tráfego durante {traffic_timeout} segundos..."):
        packets = capture_traffic(interface=selected_interface, timeout=traffic_timeout, interface_label=selected_interface_label)
        st.session_state.packets = packets
        st.session_state.last_capture_at = datetime.now().strftime('%H:%M:%S')
        st.success(f"Capturados {len(packets)} pacotes")
        traffic_by_ip, suspicious = analyze_traffic(packets, st.session_state.devices)
        st.session_state.traffic_by_ip = traffic_by_ip
        st.session_state.suspicious = suspicious

# --- Resultados ---
st.header("Resultados")

if st.session_state.last_capture_at:
    st.caption(f"Última captura: {st.session_state.last_capture_at} | Interface: {selected_interface_label}")
    st.write(f"Total de pacotes processados: {len(st.session_state.packets)}")
else:
    st.info("Ainda não existe captura. Clique em 'Capturar Tráfego' para gerar resultados.")

if st.session_state.packets:
    st.subheader("Pacotes Capturados (amostra)")
    preview_df = pd.DataFrame(st.session_state.packets).head(20)
    st.dataframe(preview_df)
elif st.session_state.last_capture_at:
    st.info("Captura concluída, mas sem pacotes válidos para mostrar na amostra.")

if st.session_state.last_capture_at:
    st.subheader("Tráfego por Dispositivo")
    if not st.session_state.traffic_by_ip.empty:
        traffic_plot_df = st.session_state.traffic_by_ip.sort_values('packets', ascending=False)
        fig_height = max(4, min(14, len(traffic_plot_df) * 0.35))
        fig, ax = plt.subplots(figsize=(12, fig_height))
        chart_labels = traffic_plot_df['source'] if 'source' in traffic_plot_df.columns else traffic_plot_df['src']
        ax.barh(chart_labels.astype(str), traffic_plot_df['packets'])
        ax.invert_yaxis()
        ax.set_xlabel("Número de Pacotes")
        ax.set_ylabel("Dispositivo de Origem")
        fig.tight_layout()
        st.pyplot(fig)
    else:
        st.info("Nenhum tráfego capturado para exibir.")

    st.subheader("Alertas de Segurança")
    if st.session_state.suspicious:
        for ip, alert in st.session_state.suspicious.items():
            st.warning(f"{ip}: {alert}")
    else:
        st.info("Nenhum alerta detetado.")

# --- Monitorização Contínua ---
if st.checkbox("Monitorização Manual (atualiza por pedido)"):
    st.info("Clique no botão abaixo para capturar e atualizar os resultados.")
    if st.button("Atualizar Monitorização"):
        packets = capture_traffic(interface=selected_interface, timeout=10, interface_label=selected_interface_label)
        st.session_state.packets = packets
        st.session_state.last_capture_at = datetime.now().strftime('%H:%M:%S')
        traffic_by_ip, suspicious = analyze_traffic(packets, st.session_state.devices)
        st.session_state.traffic_by_ip = traffic_by_ip
        st.session_state.suspicious = suspicious
        st.success(f"Capturados {len(packets)} pacotes")
        st.rerun()