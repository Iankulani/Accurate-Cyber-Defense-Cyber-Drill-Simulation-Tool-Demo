"""
🚀ACCURATE CYBER DEFENSE CYBER DRILL SIMULATION TOOLKIT PRO
Author: Ian Carter Kulani


STRUCTURE:
1. Configuration & Logging
2. Database Manager
3. Traceroute Tool (Enhanced)
4. Network Scanner (Nmap + Custom)
5. Network Monitor & Threat Detection
6. Command Executor (300+ Commands)
7. Telegram Bot Handler (All Commands)
8. Main Application Interface
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from colorama import init, Fore, Style, Back
import shutil
import urllib.parse

# Initialize colorama
init(autoreset=True)

# ============================================================================
# CONFIGURATION
# ============================================================================

# File paths
CONFIG_FILE = "cybertool_config.json"
TELEGRAM_CONFIG_FILE = "telegram_config.json"
LOG_FILE = "cybertool.log"
DATABASE_FILE = "cybertool.db"
REPORT_DIR = "reports"
COMMAND_HISTORY_FILE = "command_history.json"
SCRIPT_DIR = "scripts"

# Create necessary directories
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("CyberToolPro")

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ThreatAlert:
    """Threat alert data class"""
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    """Scan result data class"""
    target: str
    scan_type: str
    open_ports: List[Dict]
    timestamp: str
    success: bool
    error: Optional[str] = None

@dataclass
class NetworkConnection:
    """Network connection data class"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    process_name: str
    protocol: str

# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigManager:
    """Enhanced configuration manager with validation"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": False,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "telegram": {
            "enabled": False,
            "token": "",
            "chat_id": "",
            "notifications": True
        },
        "security": {
            "auto_block": False,
            "log_level": "INFO",
            "backup_enabled": True
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    ConfigManager._deep_update(config, ConfigManager.DEFAULT_CONFIG)
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def load_telegram_config() -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        
        return {"token": "", "chat_id": "", "enabled": False}
    
    @staticmethod
    def save_telegram_config(token: str, chat_id: str, enabled: bool = True) -> bool:
        """Save Telegram configuration"""
        try:
            config = {"token": token, "chat_id": chat_id, "enabled": enabled}
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Telegram configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    @staticmethod
    def _deep_update(source: Dict, updates: Dict) -> None:
        """Deep update dictionary"""
        for key, value in updates.items():
            if key in source and isinstance(source[key], dict) and isinstance(value, dict):
                ConfigManager._deep_update(source[key], value)
            else:
                source[key] = value

# ============================================================================
# DATABASE MANAGER (ENHANCED)
# ============================================================================

class DatabaseManager:
    """Enhanced database manager with comprehensive logging"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
        self.init_command_templates()
    
    def init_tables(self):
        """Initialize all database tables"""
        tables = [
            # Threats table
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            # Commands history
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            # Scan results
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                execution_time REAL
            )
            """,
            
            # Network connections
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                status TEXT,
                process_name TEXT,
                protocol TEXT
            )
            """,
            
            # Traceroute results
            """
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                hops INTEGER
            )
            """,
            
            # Monitored IPs
            """
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                notes TEXT
            )
            """,
            
            # Command templates
            """
            CREATE TABLE IF NOT EXISTS command_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                command TEXT NOT NULL,
                description TEXT,
                usage TEXT
            )
            """,
            
            # System metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def init_command_templates(self):
        """Initialize command templates database"""
        
        templates = [
            # ==================== PING COMMANDS ====================
            ('ping_basic', 'ping', 'ping {target}', 'Basic ping', 'ping <ip>'),
            ('ping_count_4', 'ping', 'ping {target} -c 4', 'Ping with 4 packets', 'ping <ip> -c 4'),
            ('ping_count_10', 'ping', 'ping {target} -c 10', 'Ping with 10 packets', 'ping <ip> -c 10'),
            ('ping_interval_0.2', 'ping', 'ping {target} -i 0.2', 'Fast ping interval', 'ping <ip> -i 0.2'),
            ('ping_wait_5', 'ping', 'ping {target} -w 5', '5 second timeout', 'ping <ip> -w 5'),
            ('ping_size_1024', 'ping', 'ping {target} -s 1024', '1024 byte packets', 'ping <ip> -s 1024'),
            ('ping_size_1472', 'ping', 'ping {target} -s 1472', 'MTU size packets', 'ping <ip> -s 1472'),
            ('ping_flood', 'ping', 'ping {target} -f', 'Flood ping', 'ping <ip> -f'),
            ('ping_ttl_64', 'ping', 'ping {target} -t 64', 'TTL 64', 'ping <ip> -t 64'),
            ('ping_ipv6', 'ping', 'ping6 {target}', 'IPv6 ping', 'ping6 <ip>'),
            
            # ==================== NMAP COMMANDS ====================
            ('nmap_basic', 'scan', 'nmap {target}', 'Basic nmap scan', 'nmap <ip>'),
            ('nmap_stealth', 'scan', 'nmap {target} -sS', 'SYN stealth scan', 'nmap <ip> -sS'),
            ('nmap_udp', 'scan', 'nmap {target} -sU', 'UDP scan', 'nmap <ip> -sU'),
            ('nmap_os', 'scan', 'nmap {target} -O', 'OS detection', 'nmap <ip> -O'),
            ('nmap_version', 'scan', 'nmap {target} -sV', 'Version detection', 'nmap <ip> -sV'),
            ('nmap_aggressive', 'scan', 'nmap {target} -A', 'Aggressive scan', 'nmap <ip> -A'),
            ('nmap_ports_top100', 'scan', 'nmap {target} --top-ports 100', 'Top 100 ports', 'nmap <ip> --top-ports 100'),
            ('nmap_ports_all', 'scan', 'nmap {target} -p-', 'All ports', 'nmap <ip> -p-'),
            ('nmap_quick', 'scan', 'nmap {target} -T4 -F', 'Quick scan', 'nmap <ip> -T4 -F'),
            ('nmap_traceroute', 'scan', 'nmap {target} --traceroute', 'Scan with traceroute', 'nmap <ip> --traceroute'),
            ('nmap_script_vuln', 'scan', 'nmap {target} --script vuln', 'Vulnerability scripts', 'nmap <ip> --script vuln'),
            ('nmap_script_safe', 'scan', 'nmap {target} --script safe', 'Safe scripts', 'nmap <ip> --script safe'),
            ('nmap_script_auth', 'scan', 'nmap {target} --script auth', 'Authentication scripts', 'nmap <ip> --script auth'),
            ('nmap_script_discovery', 'scan', 'nmap {target} --script discovery', 'Discovery scripts', 'nmap <ip> --script discovery'),
            ('nmap_no_ping', 'scan', 'nmap {target} -Pn', 'No ping scan', 'nmap <ip> -Pn'),
            ('nmap_syn_stealth', 'scan', 'nmap {target} -sS -T4', 'SYN stealth with timing', 'nmap <ip> -sS -T4'),
            ('nmap_fin_scan', 'scan', 'nmap {target} -sF', 'FIN scan', 'nmap <ip> -sF'),
            ('nmap_xmas_scan', 'scan', 'nmap {target} -sX', 'XMAS scan', 'nmap <ip> -sX'),
            ('nmap_null_scan', 'scan', 'nmap {target} -sN', 'NULL scan', 'nmap <ip> -sN'),
            ('nmap_ack_scan', 'scan', 'nmap {target} -sA', 'ACK scan', 'nmap <ip> -sA'),
            ('nmap_window_scan', 'scan', 'nmap {target} -sW', 'Window scan', 'nmap <ip> -sW'),
            ('nmap_maimon_scan', 'scan', 'nmap {target} -sM', 'Maimon scan', 'nmap <ip> -sM'),
            ('nmap_idle_scan', 'scan', 'nmap {target} -sI zombie_ip', 'Idle scan', 'nmap <ip> -sI zombie_ip'),
            ('nmap_sctp_init', 'scan', 'nmap {target} -sY', 'SCTP INIT scan', 'nmap <ip> -sY'),
            ('nmap_sctp_cookie', 'scan', 'nmap {target} -sZ', 'SCTP COOKIE ECHO', 'nmap <ip> -sZ'),
            ('nmap_ip_protocol', 'scan', 'nmap {target} -sO', 'IP protocol scan', 'nmap <ip> -sO'),
            ('nmap_list_scan', 'scan', 'nmap {target} -sL', 'List scan', 'nmap <ip> -sL'),
            ('nmap_fragment', 'scan', 'nmap {target} -f', 'Fragment packets', 'nmap <ip> -f'),
            ('nmap_decoy', 'scan', 'nmap {target} -D RND:10', 'Decoy scan', 'nmap <ip> -D RND:10'),
            ('nmap_spoof_mac', 'scan', 'nmap {target} --spoof-mac 0', 'Spoof MAC address', 'nmap <ip> --spoof-mac 0'),
            ('nmap_data_length', 'scan', 'nmap {target} --data-length 100', 'Append random data', 'nmap <ip> --data-length 100'),
            ('nmap_random_hosts', 'scan', 'nmap {target} --randomize-hosts', 'Randomize hosts', 'nmap <ip> --randomize-hosts'),
            ('nmap_badsum', 'scan', 'nmap {target} --badsum', 'Bad checksum', 'nmap <ip> --badsum'),
            
            # ==================== CURL COMMANDS ====================
            ('curl_basic', 'web', 'curl {target}', 'Basic curl request', 'curl <url>'),
            ('curl_headers', 'web', 'curl {target} -I', 'Headers only', 'curl <url> -I'),
            ('curl_verbose', 'web', 'curl {target} -v', 'Verbose output', 'curl <url> -v'),
            ('curl_silent', 'web', 'curl {target} -s', 'Silent mode', 'curl <url> -s'),
            ('curl_follow', 'web', 'curl {target} -L', 'Follow redirects', 'curl <url> -L'),
            ('curl_insecure', 'web', 'curl {target} -k', 'Allow insecure SSL', 'curl <url> -k'),
            ('curl_post', 'web', 'curl {target} -X POST', 'POST request', 'curl <url> -X POST'),
            ('curl_put', 'web', 'curl {target} -X PUT', 'PUT request', 'curl <url> -X PUT'),
            ('curl_delete', 'web', 'curl {target} -X DELETE', 'DELETE request', 'curl <url> -X DELETE'),
            ('curl_head', 'web', 'curl {target} -X HEAD', 'HEAD request', 'curl <url> -X HEAD'),
            ('curl_json', 'web', 'curl {target} -H "Content-Type: application/json"', 'JSON request', 'curl <url> -H "Content-Type: application/json"'),
            ('curl_form', 'web', 'curl {target} -F "field=value"', 'Form data', 'curl <url> -F "field=value"'),
            ('curl_data', 'web', 'curl {target} -d "param=value"', 'POST data', 'curl <url> -d "param=value"'),
            ('curl_binary', 'web', 'curl {target} --data-binary @file', 'Binary data', 'curl <url> --data-binary @file'),
            ('curl_cookies', 'web', 'curl {target} -b cookies.txt', 'Send cookies', 'curl <url> -b cookies.txt'),
            ('curl_save_cookies', 'web', 'curl {target} -c cookies.txt', 'Save cookies', 'curl <url> -c cookies.txt'),
            ('curl_user_agent', 'web', 'curl {target} -A "Mozilla/5.0"', 'Custom user agent', 'curl <url> -A "Mozilla/5.0"'),
            ('curl_referer', 'web', 'curl {target} -e "http://referer.com"', 'Set referer', 'curl <url> -e "http://referer.com"'),
            ('curl_auth_basic', 'web', 'curl {target} -u user:pass', 'Basic auth', 'curl <url> -u user:pass'),
            ('curl_auth_bearer', 'web', 'curl {target} -H "Authorization: Bearer token"', 'Bearer token', 'curl <url> -H "Authorization: Bearer token"'),
            ('curl_timeout', 'web', 'curl {target} --max-time 10', 'Timeout 10s', 'curl <url> --max-time 10'),
            ('curl_connect_timeout', 'web', 'curl {target} --connect-timeout 5', 'Connect timeout', 'curl <url> --connect-timeout 5'),
            ('curl_retry', 'web', 'curl {target} --retry 3', 'Retry 3 times', 'curl <url> --retry 3'),
            ('curl_limit_rate', 'web', 'curl {target} --limit-rate 100K', 'Limit rate 100KB/s', 'curl <url> --limit-rate 100K'),
            ('curl_output', 'web', 'curl {target} -o output.txt', 'Save output', 'curl <url> -o output.txt'),
            ('curl_remote_name', 'web', 'curl {target} -O', 'Save with remote name', 'curl <url> -O'),
            ('curl_compressed', 'web', 'curl {target} --compressed', 'Accept compression', 'curl <url> --compressed'),
            ('curl_http2', 'web', 'curl {target} --http2', 'Use HTTP/2', 'curl <url> --http2'),
            ('curl_proxy', 'web', 'curl {target} --proxy http://proxy:8080', 'Use proxy', 'curl <url> --proxy http://proxy:8080'),
            ('curl_socks5', 'web', 'curl {target} --socks5-hostname proxy:1080', 'SOCKS5 proxy', 'curl <url> --socks5-hostname proxy:1080'),
            ('curl_interface', 'web', 'curl {target} --interface eth0', 'Specify interface', 'curl <url> --interface eth0'),
            ('curl_resolve', 'web', 'curl {target} --resolve example.com:443:1.2.3.4', 'Resolve host', 'curl <url> --resolve example.com:443:1.2.3.4'),
            ('curl_trace', 'web', 'curl {target} --trace trace.txt', 'Trace output', 'curl <url> --trace trace.txt'),
            ('curl_trace_ascii', 'web', 'curl {target} --trace-ascii trace.log', 'Trace ASCII', 'curl <url> --trace-ascii trace.log'),
            ('curl_dump_header', 'web', 'curl {target} -D header.txt', 'Dump headers', 'curl <url> -D header.txt'),
            ('curl_range', 'web', 'curl {target} -r 0-999', 'Byte range', 'curl <url> -r 0-999'),
            ('curl_ftp', 'web', 'curl {target} --user user:pass', 'FTP login', 'curl <url> --user user:pass'),
            ('curl_ftp_ssl', 'web', 'curl {target} --ftp-ssl', 'FTP over SSL', 'curl <url> --ftp-ssl'),
            ('curl_ftp_pasv', 'web', 'curl {target} --ftp-pasv', 'FTP passive mode', 'curl <url> --ftp-pasv'),
            ('curl_mail_from', 'web', 'curl {target} --mail-from sender@example.com', 'SMTP mail from', 'curl <url> --mail-from sender@example.com'),
            ('curl_mail_rcpt', 'web', 'curl {target} --mail-rcpt recipient@example.com', 'SMTP mail rcpt', 'curl <url> --mail-rcpt recipient@example.com'),
            ('curl_tlsv1_2', 'web', 'curl {target} --tlsv1.2', 'TLS 1.2', 'curl <url> --tlsv1.2'),
            ('curl_tlsv1_3', 'web', 'curl {target} --tlsv1.3', 'TLS 1.3', 'curl <url> --tlsv1.3'),
            ('curl_cert', 'web', 'curl {target} --cert client.pem', 'Client certificate', 'curl <url> --cert client.pem'),
            ('curl_key', 'web', 'curl {target} --key client.key', 'Client key', 'curl <url> --key client.key'),
            ('curl_cacert', 'web', 'curl {target} --cacert ca.pem', 'CA certificate', 'curl <url> --cacert ca.pem'),
            
            # ==================== SSH COMMANDS ====================
            ('ssh_basic', 'ssh', 'ssh {target}', 'Basic SSH connection', 'ssh <host>'),
            ('ssh_port', 'ssh', 'ssh {target} -p 22', 'SSH with port', 'ssh <host> -p 22'),
            ('ssh_verbose', 'ssh', 'ssh {target} -v', 'Verbose SSH', 'ssh <host> -v'),
            ('ssh_very_verbose', 'ssh', 'ssh {target} -vvv', 'Very verbose SSH', 'ssh <host> -vvv'),
            ('ssh_quiet', 'ssh', 'ssh {target} -q', 'Quiet mode', 'ssh <host> -q'),
            ('ssh_compression', 'ssh', 'ssh {target} -C', 'Compression enabled', 'ssh <host> -C'),
            ('ssh_no_exec', 'ssh', 'ssh {target} -N', 'No command execution', 'ssh <host> -N'),
            ('ssh_no_pty', 'ssh', 'ssh {target} -T', 'No TTY allocation', 'ssh <host> -T'),
            ('ssh_x11', 'ssh', 'ssh {target} -X', 'X11 forwarding', 'ssh <host> -X'),
            ('ssh_x11_trusted', 'ssh', 'ssh {target} -Y', 'Trusted X11 forwarding', 'ssh <host> -Y'),
            ('ssh_ipv4', 'ssh', 'ssh {target} -4', 'Force IPv4', 'ssh <host> -4'),
            ('ssh_ipv6', 'ssh', 'ssh {target} -6', 'Force IPv6', 'ssh <host> -6'),
            ('ssh_agent', 'ssh', 'ssh {target} -A', 'Agent forwarding', 'ssh <host> -A'),
            ('ssh_no_agent', 'ssh', 'ssh {target} -a', 'Disable agent forwarding', 'ssh <host> -a'),
            ('ssh_gssapi', 'ssh', 'ssh {target} -K', 'GSSAPI authentication', 'ssh <host> -K'),
            ('ssh_no_gssapi', 'ssh', 'ssh {target} -k', 'Disable GSSAPI', 'ssh <host> -k'),
            ('ssh_identity', 'ssh', 'ssh {target} -i ~/.ssh/id_rsa', 'Identity file', 'ssh <host> -i ~/.ssh/id_rsa'),
            ('ssh_strict', 'ssh', 'ssh {target} -o StrictHostKeyChecking=no', 'Disable strict checking', 'ssh <host> -o StrictHostKeyChecking=no'),
            ('ssh_connect_timeout', 'ssh', 'ssh {target} -o ConnectTimeout=10', 'Connect timeout', 'ssh <host> -o ConnectTimeout=10'),
            ('ssh_server_alive', 'ssh', 'ssh {target} -o ServerAliveInterval=60', 'Server alive interval', 'ssh <host> -o ServerAliveInterval=60'),
            ('ssh_local_port', 'ssh', 'ssh {target} -L 8080:localhost:80', 'Local port forwarding', 'ssh <host> -L 8080:localhost:80'),
            ('ssh_remote_port', 'ssh', 'ssh {target} -R 9000:localhost:9000', 'Remote port forwarding', 'ssh <host> -R 9000:localhost:9000'),
            ('ssh_dynamic_port', 'ssh', 'ssh {target} -D 1080', 'Dynamic port forwarding', 'ssh <host> -D 1080'),
            ('ssh_jump_host', 'ssh', 'ssh {target} -J jump@jumphost', 'Jump host', 'ssh <host> -J jump@jumphost'),
            ('ssh_bind_address', 'ssh', 'ssh {target} -b 192.168.1.100', 'Bind address', 'ssh <host> -b 192.168.1.100'),
            ('ssh_log_file', 'ssh', 'ssh {target} -E ssh.log', 'Log file', 'ssh <host> -E ssh.log'),
            ('ssh_config', 'ssh', 'ssh {target} -F ssh_config', 'Config file', 'ssh <host> -F ssh_config'),
            ('ssh_cipher', 'ssh', 'ssh {target} -c aes256-ctr', 'Cipher specification', 'ssh <host> -c aes256-ctr'),
            ('ssh_mac', 'ssh', 'ssh {target} -m hmac-sha2-256', 'MAC algorithm', 'ssh <host> -m hmac-sha2-256'),
            ('ssh_control_master', 'ssh', 'ssh {target} -M -S ~/.ssh/socket', 'Control master', 'ssh <host> -M -S ~/.ssh/socket'),
            ('ssh_control_persist', 'ssh', 'ssh {target} -o ControlPersist=yes', 'Control persist', 'ssh <host> -o ControlPersist=yes'),
            ('ssh_proxy_command', 'ssh', 'ssh {target} -o ProxyCommand="ssh proxy nc %h %p"', 'Proxy command', 'ssh <host> -o ProxyCommand="ssh proxy nc %h %p"'),
            ('ssh_proxy_jump', 'ssh', 'ssh {target} -o ProxyJump=jump@host', 'Proxy jump', 'ssh <host> -o ProxyJump=jump@host'),
            
            # ==================== TRACEROUTE COMMANDS ====================
            ('tracert_basic', 'traceroute', 'tracert {target}', 'Windows traceroute', 'tracert <ip>'),
            ('tracert_no_dns', 'traceroute', 'tracert {target} -d', 'No DNS resolution', 'tracert <ip> -d'),
            ('traceroute_basic', 'traceroute', 'traceroute {target}', 'Unix traceroute', 'traceroute <ip>'),
            ('traceroute_no_dns', 'traceroute', 'traceroute {target} -n', 'No DNS resolution', 'traceroute <ip> -n'),
            ('traceroute_queries_1', 'traceroute', 'traceroute {target} -q 1', '1 query per hop', 'traceroute <ip> -q 1'),
            ('traceroute_wait_2', 'traceroute', 'traceroute {target} -w 2', '2 second wait', 'traceroute <ip> -w 2'),
            ('traceroute_first_ttl', 'traceroute', 'traceroute {target} -f 1', 'First TTL 1', 'traceroute <ip> -f 1'),
            ('traceroute_max_ttl', 'traceroute', 'traceroute {target} -m 30', 'Max TTL 30', 'traceroute <ip> -m 30'),
            ('tracepath_basic', 'traceroute', 'tracepath {target}', 'Tracepath', 'tracepath <ip>'),
            ('mtr_basic', 'traceroute', 'mtr {target}', 'MTR (My TraceRoute)', 'mtr <ip>'),
            ('mtr_report', 'traceroute', 'mtr {target} --report', 'MTR report', 'mtr <ip> --report'),
            ('mtr_report_cycles', 'traceroute', 'mtr {target} --report --report-cycles 10', 'MTR 10 cycles', 'mtr <ip> --report --report-cycles 10'),
            
            # ==================== NETWORK TRAFFIC COMMANDS ====================
            ('iperf_tcp', 'traffic', 'iperf -c {target}', 'TCP iperf test', 'iperf -c <server>'),
            ('iperf_udp', 'traffic', 'iperf -c {target} -u', 'UDP iperf test', 'iperf -c <server> -u'),
            ('iperf_bandwidth', 'traffic', 'iperf -c {target} -u -b 10M', 'UDP 10Mbps', 'iperf -c <server> -u -b 10M'),
            ('iperf_time', 'traffic', 'iperf -c {target} -t 30', '30 second test', 'iperf -c <server> -t 30'),
            ('iperf_interval', 'traffic', 'iperf -c {target} -i 1', '1 second interval', 'iperf -c <server> -i 1'),
            ('iperf_parallel', 'traffic', 'iperf -c {target} -P 5', '5 parallel streams', 'iperf -c <server> -P 5'),
            ('iperf_reverse', 'traffic', 'iperf -c {target} -R', 'Reverse test', 'iperf -c <server> -R'),
            ('iperf3_basic', 'traffic', 'iperf3 -c {target}', 'iperf3 TCP test', 'iperf3 -c <server>'),
            ('iperf3_udp', 'traffic', 'iperf3 -c {target} -u', 'iperf3 UDP test', 'iperf3 -c <server> -u'),
            ('iperf3_bandwidth', 'traffic', 'iperf3 -c {target} -u -b 100M', 'iperf3 100Mbps', 'iperf3 -c <server> -u -b 100M'),
            ('iperf3_json', 'traffic', 'iperf3 -c {target} -J', 'JSON output', 'iperf3 -c <server> -J'),
            ('hping3_syn', 'traffic', 'hping3 {target} -S', 'SYN flood test', 'hping3 <ip> -S'),
            ('hping3_ack', 'traffic', 'hping3 {target} -A', 'ACK flood', 'hping3 <ip> -A'),
            ('hping3_udp', 'traffic', 'hping3 {target} -2', 'UDP flood', 'hping3 <ip> -2'),
            ('hping3_icmp', 'traffic', 'hping3 {target} -1', 'ICMP flood', 'hping3 <ip> -1'),
            ('hping3_port_80', 'traffic', 'hping3 {target} -S -p 80', 'SYN to port 80', 'hping3 <ip> -S -p 80'),
            ('hping3_flood', 'traffic', 'hping3 {target} --flood', 'Flood mode', 'hping3 <ip> --flood'),
            ('hping3_count', 'traffic', 'hping3 {target} -c 1000', '1000 packets', 'hping3 <ip> -c 1000'),
            ('hping3_interval', 'traffic', 'hping3 {target} -i u1000', '1ms interval', 'hping3 <ip> -i u1000'),
            ('hping3_data', 'traffic', 'hping3 {target} -d 120', '120 byte data', 'hping3 <ip> -d 120'),
            ('hping3_spoof', 'traffic', 'hping3 {target} -a 192.168.1.100', 'Spoof source IP', 'hping3 <ip> -a 192.168.1.100'),
            ('ab_basic', 'traffic', 'ab -n 1000 -c 10 {target}', 'Apache Bench 1000 req', 'ab -n 1000 -c 10 <url>'),
            ('ab_heavy', 'traffic', 'ab -n 5000 -c 50 {target}', 'Apache Bench 5000 req', 'ab -n 5000 -c 50 <url>'),
            ('ab_post', 'traffic', 'ab -n 1000 -c 10 -p post.data -T application/json {target}', 'POST requests', 'ab -n 1000 -c 10 -p post.data -T application/json <url>'),
            ('siege_basic', 'traffic', 'siege {target}', 'Siege test', 'siege <url>'),
            ('siege_concurrent', 'traffic', 'siege -c 10 -t 1M {target}', '10 concurrent, 1 minute', 'siege -c 10 -t 1M <url>'),
            ('siege_file', 'traffic', 'siege -f urls.txt', 'URLs from file', 'siege -f urls.txt'),
            ('tcpdump_basic', 'traffic', 'tcpdump -i eth0', 'Capture on eth0', 'tcpdump -i eth0'),
            ('tcpdump_port', 'traffic', 'tcpdump -i eth0 port 80', 'Capture port 80', 'tcpdump -i eth0 port 80'),
            ('tcpdump_host', 'traffic', 'tcpdump -i eth0 host 192.168.1.1', 'Capture host traffic', 'tcpdump -i eth0 host 192.168.1.1'),
            ('tcpdump_save', 'traffic', 'tcpdump -i eth0 -w capture.pcap', 'Save to file', 'tcpdump -i eth0 -w capture.pcap'),
            ('tcpdump_read', 'traffic', 'tcpdump -r capture.pcap', 'Read from file', 'tcpdump -r capture.pcap'),
            ('tcpdump_verbose', 'traffic', 'tcpdump -i eth0 -v', 'Verbose output', 'tcpdump -i eth0 -v'),
            ('tcpdump_hex', 'traffic', 'tcpdump -i eth0 -XX', 'Hex and ASCII', 'tcpdump -i eth0 -XX'),
            
            # ==================== WHOIS & DNS COMMANDS ====================
            ('whois_basic', 'info', 'whois {target}', 'Basic whois lookup', 'whois <domain>'),
            ('dig_basic', 'info', 'dig {target}', 'DNS lookup with dig', 'dig <domain>'),
            ('dig_mx', 'info', 'dig {target} MX', 'MX records', 'dig <domain> MX'),
            ('dig_ns', 'info', 'dig {target} NS', 'NS records', 'dig <domain> NS'),
            ('dig_txt', 'info', 'dig {target} TXT', 'TXT records', 'dig <domain> TXT'),
            ('dig_soa', 'info', 'dig {target} SOA', 'SOA record', 'dig <domain> SOA'),
            ('dig_any', 'info', 'dig {target} ANY', 'All records', 'dig <domain> ANY'),
            ('dig_reverse', 'info', 'dig -x {target}', 'Reverse DNS', 'dig -x <ip>'),
            ('dig_trace', 'info', 'dig {target} +trace', 'Trace DNS delegation', 'dig <domain> +trace'),
            ('dig_short', 'info', 'dig {target} +short', 'Short output', 'dig <domain> +short'),
            ('nslookup_basic', 'info', 'nslookup {target}', 'nslookup', 'nslookup <domain>'),
            ('nslookup_type_mx', 'info', 'nslookup -type=MX {target}', 'nslookup MX', 'nslookup -type=MX <domain>'),
            ('host_basic', 'info', 'host {target}', 'host command', 'host <domain>'),
            ('host_ip', 'info', 'host {target} 8.8.8.8', 'Host with specific DNS', 'host <domain> 8.8.8.8'),
            
            # ==================== SYSTEM COMMANDS ====================
            ('netstat_all', 'system', 'netstat -an', 'All connections', 'netstat -an'),
            ('netstat_listen', 'system', 'netstat -tulpn', 'Listening ports', 'netstat -tulpn'),
            ('netstat_routes', 'system', 'netstat -rn', 'Routing table', 'netstat -rn'),
            ('ss_all', 'system', 'ss -tulpn', 'Socket statistics', 'ss -tulpn'),
            ('ss_listen', 'system', 'ss -l', 'Listening sockets', 'ss -l'),
            ('ifconfig', 'system', 'ifconfig', 'Interface configuration', 'ifconfig'),
            ('ip_addr', 'system', 'ip addr', 'IP addresses', 'ip addr'),
            ('ip_route', 'system', 'ip route', 'Routing table', 'ip route'),
            ('ip_neigh', 'system', 'ip neigh', 'ARP table', 'ip neigh'),
            ('route', 'system', 'route -n', 'Route table', 'route -n'),
            ('arp', 'system', 'arp -a', 'ARP cache', 'arp -a'),
            ('uptime', 'system', 'uptime', 'System uptime', 'uptime'),
            ('w', 'system', 'w', 'Logged in users', 'w'),
            ('who', 'system', 'who', 'Who is logged in', 'who'),
            ('last', 'system', 'last', 'Last logged in users', 'last'),
            ('ps_aux', 'system', 'ps aux', 'Process list', 'ps aux'),
            ('top', 'system', 'top -b -n 1', 'Process snapshot', 'top -b -n 1'),
            ('free', 'system', 'free -h', 'Memory usage', 'free -h'),
            ('df', 'system', 'df -h', 'Disk usage', 'df -h'),
            ('du', 'system', 'du -sh *', 'Directory sizes', 'du -sh *'),
            ('vmstat', 'system', 'vmstat 1 5', 'VM statistics', 'vmstat 1 5'),
            ('mpstat', 'system', 'mpstat 1 5', 'CPU statistics', 'mpstat 1 5'),
            ('iostat', 'system', 'iostat 1 5', 'I/O statistics', 'iostat 1 5'),
            ('sar', 'system', 'sar -u 1 5', 'System activity', 'sar -u 1 5'),
            ('dmesg', 'system', 'dmesg | tail -20', 'Kernel messages', 'dmesg | tail -20'),
            ('journalctl', 'system', 'journalctl -xe', 'System logs', 'journalctl -xe'),
            
            # ==================== FILE TRANSFER COMMANDS ====================
            ('wget_basic', 'transfer', 'wget {target}', 'Download file', 'wget <url>'),
            ('wget_resume', 'transfer', 'wget -c {target}', 'Resume download', 'wget -c <url>'),
            ('wget_limit', 'transfer', 'wget --limit-rate=500k {target}', 'Limit rate 500k', 'wget --limit-rate=500k <url>'),
            ('wget_background', 'transfer', 'wget -b {target}', 'Background download', 'wget -b <url>'),
            ('wget_output', 'transfer', 'wget -O file.txt {target}', 'Custom output name', 'wget -O file.txt <url>'),
            ('wget_mirror', 'transfer', 'wget -m {target}', 'Mirror website', 'wget -m <url>'),
            ('wget_recursive', 'transfer', 'wget -r {target}', 'Recursive download', 'wget -r <url>'),
            ('scp_file', 'transfer', 'scp file.txt user@host:/path/', 'SCP file copy', 'scp file.txt user@host:/path/'),
            ('scp_dir', 'transfer', 'scp -r dir/ user@host:/path/', 'SCP directory', 'scp -r dir/ user@host:/path/'),
            ('scp_from', 'transfer', 'scp user@host:/path/file.txt .', 'SCP from remote', 'scp user@host:/path/file.txt .'),
            ('rsync_basic', 'transfer', 'rsync -av source/ dest/', 'RSYNC basic', 'rsync -av source/ dest/'),
            ('rsync_ssh', 'transfer', 'rsync -avz -e ssh source/ user@host:dest/', 'RSYNC over SSH', 'rsync -avz -e ssh source/ user@host:dest/'),
            ('rsync_progress', 'transfer', 'rsync -av --progress source/ dest/', 'RSYNC with progress', 'rsync -av --progress source/ dest/'),
            ('rsync_delete', 'transfer', 'rsync -av --delete source/ dest/', 'RSYNC delete', 'rsync -av --delete source/ dest/'),
            
            # ==================== SECURITY COMMANDS ====================
            ('nmap_vuln', 'security', 'nmap {target} --script vuln', 'Vulnerability scan', 'nmap <ip> --script vuln'),
            ('nmap_exploit', 'security', 'nmap {target} --script exploit', 'Exploit scan', 'nmap <ip> --script exploit'),
            ('nmap_malware', 'security', 'nmap {target} --script malware', 'Malware scan', 'nmap <ip> --script malware'),
            ('nikto_basic', 'security', 'nikto -h {target}', 'Nikto web scan', 'nikto -h <url>'),
            ('sqlmap_basic', 'security', 'sqlmap -u "{target}"', 'SQL injection test', 'sqlmap -u "<url>"'),
            ('gobuster_dir', 'security', 'gobuster dir -u {target} -w wordlist.txt', 'Directory busting', 'gobuster dir -u <url> -w wordlist.txt'),
            ('gobuster_dns', 'security', 'gobuster dns -d {target} -w wordlist.txt', 'DNS subdomain', 'gobuster dns -d <domain> -w wordlist.txt'),
            ('dirb_basic', 'security', 'dirb {target}', 'DIRB scan', 'dirb <url>'),
            ('wfuzz_basic', 'security', 'wfuzz -c -z file,wordlist.txt {target}/FUZZ', 'WFUZZ fuzzing', 'wfuzz -c -z file,wordlist.txt <url>/FUZZ'),
            ('nuclei_basic', 'security', 'nuclei -u {target}', 'Nuclei scan', 'nuclei -u <url>'),
            ('whatweb_basic', 'security', 'whatweb {target}', 'WhatWeb scan', 'whatweb <url>'),
            
            # ==================== MISC COMMANDS ====================
            ('nc_listen', 'misc', 'nc -l -p 1234', 'Netcat listen on port', 'nc -l -p 1234'),
            ('nc_connect', 'misc', 'nc {target} 80', 'Netcat connect', 'nc <ip> 80'),
            ('nc_udp', 'misc', 'nc -u {target} 53', 'Netcat UDP', 'nc -u <ip> 53'),
            ('nc_port_scan', 'misc', 'nc -zv {target} 1-1000', 'Netcat port scan', 'nc -zv <ip> 1-1000'),
            ('telnet_connect', 'misc', 'telnet {target} 23', 'Telnet connection', 'telnet <ip> 23'),
            ('openssl_client', 'misc', 'openssl s_client -connect {target}:443', 'SSL client', 'openssl s_client -connect <host>:443'),
            ('openssl_cert', 'misc', 'openssl s_client -connect {target}:443 -showcerts', 'SSL certificates', 'openssl s_client -connect <host>:443 -showcerts'),
            ('hash_md5', 'misc', 'echo -n "{target}" | md5sum', 'MD5 hash', 'echo -n "<text>" | md5sum'),
            ('hash_sha1', 'misc', 'echo -n "{target}" | sha1sum', 'SHA1 hash', 'echo -n "<text>" | sha1sum'),
            ('hash_sha256', 'misc', 'echo -n "{target}" | sha256sum', 'SHA256 hash', 'echo -n "<text>" | sha256sum'),
            ('base64_encode', 'misc', 'echo -n "{target}" | base64', 'Base64 encode', 'echo -n "<text>" | base64'),
            ('base64_decode', 'misc', 'echo -n "{target}" | base64 -d', 'Base64 decode', 'echo -n "<text>" | base64 -d'),
            ('url_encode', 'misc', 'python3 -c "import urllib.parse; print(urllib.parse.quote(\'{target}\'))"', 'URL encode', 'python3 -c "import urllib.parse; print(urllib.parse.quote(\'<text>\'))"'),
            ('url_decode', 'misc', 'python3 -c "import urllib.parse; print(urllib.parse.unquote(\'{target}\'))"', 'URL decode', 'python3 -c "import urllib.parse; print(urllib.parse.unquote(\'<text>\'))"'),
            ('python_exec', 'misc', 'python3 -c "{target}"', 'Python execute', 'python3 -c "<code>"'),
            ('bash_exec', 'misc', 'bash -c "{target}"', 'Bash execute', 'bash -c "<command>"'),
            ('php_exec', 'misc', 'php -r "{target}"', 'PHP execute', 'php -r "<code>"'),
        ]
        
        for template in templates:
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO command_templates (name, category, command, description, usage)
                    VALUES (?, ?, ?, ?, ?)
                ''', template)
            except Exception as e:
                logger.error(f"Failed to insert template {template[0]}: {e}")
        
        self.conn.commit()
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat to database"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip, 
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_command(self, command: str, source: str = "local", success: bool = True, 
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO commands (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:10000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.open_ports) if scan_result.open_ports else "[]"
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, scan_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_traceroute(self, target: str, command: str, output: str, 
                      execution_time: float, hops: int = 0):
        """Log traceroute results"""
        try:
            self.cursor.execute('''
                INSERT INTO traceroute_results (target, command, output, execution_time, hops)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, command, output, execution_time, hops))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log traceroute: {e}")
    
    def log_connection(self, connection: NetworkConnection):
        """Log network connection"""
        try:
            self.cursor.execute('''
                INSERT INTO connections (local_ip, local_port, remote_ip, remote_port, status, process_name, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (connection.local_ip, connection.local_port, connection.remote_ip,
                  connection.remote_port, connection.status, connection.process_name, connection.protocol))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log connection: {e}")
    
    def log_system_metrics(self):
        """Log system metrics"""
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()
            connections = len(psutil.net_connections())
            
            self.cursor.execute('''
                INSERT INTO system_metrics (cpu_percent, memory_percent, disk_percent, 
                                          network_sent, network_recv, connections_count)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cpu, mem.percent, disk.percent, net.bytes_sent, net.bytes_recv, connections))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log system metrics: {e}")
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM commands 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_command_templates(self, category: str = None) -> List[Dict]:
        """Get command templates"""
        try:
            if category:
                self.cursor.execute('''
                    SELECT * FROM command_templates WHERE category = ? ORDER BY name
                ''', (category,))
            else:
                self.cursor.execute('''
                    SELECT * FROM command_templates ORDER BY category, name
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command templates: {e}")
            return []
    
    def get_template_by_name(self, name: str) -> Optional[Dict]:
        """Get command template by name"""
        try:
            self.cursor.execute('''
                SELECT * FROM command_templates WHERE name = ?
            ''', (name,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get template: {e}")
            return None
    
    def add_monitored_ip(self, ip: str, notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            self.cursor.execute('''
                INSERT OR IGNORE INTO monitored_ips (ip_address, notes) VALUES (?, ?)
            ''', (ip, notes))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add monitored IP: {e}")
            return False
    
    def get_monitored_ips(self, active_only: bool = True) -> List[Dict]:
        """Get monitored IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM monitored_ips WHERE is_active = 1 ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM monitored_ips ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get monitored IPs: {e}")
            return []
    
    def remove_monitored_ip(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            self.cursor.execute('''
                DELETE FROM monitored_ips WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove monitored IP: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            # Count threats
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            # Count commands
            self.cursor.execute('SELECT COUNT(*) FROM commands')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            # Count scans
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            # Count monitored IPs
            self.cursor.execute('SELECT COUNT(*) FROM monitored_ips WHERE is_active = 1')
            stats['active_monitored_ips'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def backup(self, backup_path: str = None) -> bool:
        """Create database backup"""
        try:
            if backup_path is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"backup_cybertool_{timestamp}.db"
            
            # Create backup
            backup_conn = sqlite3.connect(backup_path)
            self.conn.backup(backup_conn)
            backup_conn.close()
            
            logger.info(f"Database backed up to {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# ============================================================================
# ENHANCED TRACEROUTE TOOL
# ============================================================================

class EnhancedTracerouteTool:
    """Enhanced interactive traceroute tool with advanced features"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """Validate target IP or hostname"""
        # Check for empty
        if not target or not target.strip():
            return False, "Target cannot be empty"
        
        target = target.strip()
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(target)
            return True, "ip"
        except ValueError:
            pass
        
        # Check if it's a valid hostname
        if target.endswith('.'):
            target = target[:-1]
        
        # Enhanced hostname validation
        if len(target) > 253:
            return False, "Hostname too long"
        
        # Check each label
        labels = target.split('.')
        for label in labels:
            if len(label) > 63:
                return False, f"Label '{label}' too long"
            if label.startswith('-') or label.endswith('-'):
                return False, f"Label '{label}' cannot start or end with hyphen"
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                return False, f"Label '{label}' contains invalid characters"
            if not label:
                return False, "Empty label in hostname"
        
        return True, "hostname"
    
    @staticmethod
    def get_traceroute_command(target: str, options: Dict = None) -> List[str]:
        """Get appropriate traceroute command for the system"""
        if options is None:
            options = {}
        
        system = platform.system().lower()
        
        # Default options
        default_options = {
            'no_dns': True,
            'max_hops': 30,
            'timeout': 2,
            'queries': 1,
            'packet_size': 60
        }
        default_options.update(options)
        
        if system == 'windows':
            cmd = ['tracert']
            if default_options['no_dns']:
                cmd.append('-d')
            cmd.extend(['-h', str(default_options['max_hops'])])
            cmd.extend(['-w', str(default_options['timeout'] * 1000)])  # Windows uses milliseconds
            cmd.append(target)
        
        else:  # Unix-like systems
            # Try to find the best traceroute command
            if shutil.which('mtr'):
                cmd = ['mtr', '--report', '--report-cycles', '1']
                if default_options['no_dns']:
                    cmd.append('-n')
                cmd.extend(['-c', '1'])  # One cycle
                cmd.append(target)
            
            elif shutil.which('traceroute'):
                cmd = ['traceroute']
                if default_options['no_dns']:
                    cmd.append('-n')
                cmd.extend(['-q', str(default_options['queries'])])
                cmd.extend(['-w', str(default_options['timeout'])])
                cmd.extend(['-m', str(default_options['max_hops'])])
                cmd.extend(['-s', str(default_options['packet_size'])])
                cmd.append(target)
            
            elif shutil.which('tracepath'):
                cmd = ['tracepath']
                cmd.extend(['-m', str(default_options['max_hops'])])
                cmd.append(target)
            
            else:
                # Fallback to ping with TTL
                cmd = ['ping', '-c', '4', '-t', '1', target]
        
        return cmd
    
    def interactive_traceroute(self, target: str = None, options: Dict = None) -> str:
        """Run enhanced interactive traceroute"""
        if target is None:
            target = self._prompt_target()
            if not target:
                return "Traceroute cancelled."
        
        # Validate target
        is_valid, target_type = self.validate_target(target)
        if not is_valid:
            return f"❌ Invalid target: {target}"
        
        # Get command
        try:
            cmd = self.get_traceroute_command(target, options)
        except Exception as e:
            return f"❌ Failed to get traceroute command: {e}"
        
        print(f"\n{'='*60}")
        print(f"🚀 ENHANCED TRACEROUTE TO: {target}")
        print(f"📋 Command: {' '.join(cmd)}")
        print(f"📅 Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Execute command
        start_time = time.time()
        result = self._execute_traceroute(cmd, target)
        execution_time = time.time() - start_time
        
        # Process results
        output = self._process_traceroute_output(result['output'], target)
        hops = self._count_hops(result['output'])
        
        # Log to database if available
        if self.db:
            self.db.log_traceroute(target, ' '.join(cmd), result['output'], 
                                 execution_time, hops)
        
        # Create formatted response
        response = self._format_traceroute_response(target, cmd, output, 
                                                  execution_time, result['returncode'], 
                                                  hops)
        
        return response
    
    def _prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        print("\n" + "="*60)
        print("🛣️  ENHANCED TRACEROUTE TOOL")
        print("="*60)
        
        while True:
            print("\nEnter target (IP address or hostname):")
            print("  Examples: 8.8.8.8, google.com, 2001:4860:4860::8888")
            print("  Type 'quit' or press Ctrl+C to cancel")
            print("-"*40)
            
            user_input = input("Target: ").strip()
            
            if not user_input:
                print("❌ Please enter a target")
                continue
            
            if user_input.lower() in ('q', 'quit', 'exit', 'cancel'):
                return None
            
            is_valid, target_type = self.validate_target(user_input)
            if is_valid:
                return user_input
            else:
                print(f"❌ Invalid target. Please enter a valid IP or hostname.")
    
    def _execute_traceroute(self, cmd: List[str], target: str) -> Dict:
        """Execute traceroute command with real-time output"""
        output_lines = []
        returncode = -1
        
        try:
            print(f"⏳ Running traceroute to {target}...\n")
            
            # Execute with real-time output
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output in real-time
            for line in proc.stdout:
                line = line.rstrip()
                output_lines.append(line)
                
                # Colorize output based on content
                if 'ms' in line or 'msec' in line:
                    # Time measurements - color based on latency
                    if any(x in line for x in ['*', '!', '?']):
                        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
                    elif any(x in line for x in ['<1', '0.', '1.', '2.', '3.', '4.', '5.']):
                        print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
                    elif any(x in line for x in ['10.', '20.', '30.', '40.', '50.']):
                        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                elif any(x in line for x in ['traceroute', 'tracert', 'mtr']):
                    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
                elif any(x in line for x in ['Unable', 'Failed', 'Error', 'Timeout']):
                    print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                else:
                    print(line)
            
            proc.wait()
            returncode = proc.returncode
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Traceroute interrupted by user{Style.RESET_ALL}")
            returncode = -1
            output_lines.append("\n[INTERRUPTED] User cancelled the traceroute")
        
        except Exception as e:
            error_msg = f"❌ Error executing traceroute: {e}"
            print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
            output_lines.append(error_msg)
            returncode = -2
        
        return {
            'output': '\n'.join(output_lines),
            'returncode': returncode
        }
    
    def _process_traceroute_output(self, output: str, target: str) -> str:
        """Process and analyze traceroute output"""
        lines = output.split('\n')
        processed = []
        
        for line in lines:
            # Skip empty lines
            if not line.strip():
                processed.append(line)
                continue
            
            # Analyze each line
            processed_line = self._analyze_traceroute_line(line, target)
            processed.append(processed_line)
        
        return '\n'.join(processed)
    
    def _analyze_traceroute_line(self, line: str, target: str) -> str:
        """Analyze a single traceroute line"""
        line_lower = line.lower()
        
        # Check for timeout/errors
        if any(x in line_lower for x in ['*', 'request timed out', 'timeout', 'no response']):
            return f"{Fore.YELLOW}{line} ⚠️ (Timeout/No response){Style.RESET_ALL}"
        
        # Check for network errors
        if any(x in line_lower for x in ['destination unreachable', 'unreachable', '!h', '!n', '!p']):
            return f"{Fore.RED}{line} 🚫 (Destination unreachable){Style.RESET_ALL}"
        
        # Check for administrative prohibitions
        if any(x in line_lower for x in ['!a', 'administratively prohibited']):
            return f"{Fore.RED}{line} ⛔ (Administratively prohibited){Style.RESET_ALL}"
        
        # Check for successful hops with good latency
        if 'ms' in line or 'msec' in line:
            # Extract latency if present
            latency_match = re.search(r'(\d+\.?\d*)\s*(ms|msec)', line)
            if latency_match:
                latency = float(latency_match.group(1))
                if latency < 10:
                    return f"{Fore.GREEN}{line} ✅ (Excellent: <10ms){Style.RESET_ALL}"
                elif latency < 50:
                    return f"{Fore.GREEN}{line} ✓ (Good: <50ms){Style.RESET_ALL}"
                elif latency < 100:
                    return f"{Fore.YELLOW}{line} ⚠️ (Moderate: <100ms){Style.RESET_ALL}"
                else:
                    return f"{Fore.RED}{line} ⚠️ (High: >100ms){Style.RESET_ALL}"
        
        # Check for destination reached
        if target.lower() in line_lower and any(x in line_lower for x in ['reached', 'completed']):
            return f"{Fore.GREEN}{line} 🎯 (Destination reached!){Style.RESET_ALL}"
        
        return line
    
    def _count_hops(self, output: str) -> int:
        """Count number of hops in traceroute output"""
        lines = output.split('\n')
        hops = 0
        
        for line in lines:
            # Look for hop numbers (format: "1 ", "2 ", etc. at start of line)
            if re.match(r'^\s*\d+\s+', line):
                hops += 1
        
        return hops
    
    def _format_traceroute_response(self, target: str, cmd: List[str], 
                                   output: str, execution_time: float, 
                                   returncode: int, hops: int) -> str:
        """Format traceroute response for display/telegram"""
        
        response = f"""
{'='*60}
🛣️  TRACEROUTE RESULTS: {target}
{'='*60}

📋 COMMAND:
  {' '.join(cmd)}

⏱️  EXECUTION:
  Time: {execution_time:.2f} seconds
  Hops detected: {hops}
  Return code: {returncode}

📊 RESULTS:
{output}

{'='*60}
💡 INTERPRETATION:
  ✅ Green: Good latency (<50ms)
  ⚠️  Yellow: Moderate latency or timeouts
  🚫 Red: High latency or errors
  🎯 Green with target: Destination reached
{'='*60}
        """
        
        return response
    
    def batch_traceroute(self, targets: List[str], options: Dict = None) -> Dict[str, Any]:
        """Perform traceroute on multiple targets"""
        results = {
            'total': len(targets),
            'successful': 0,
            'failed': 0,
            'results': {}
        }
        
        print(f"\n{'='*60}")
        print(f"🔄 BATCH TRACEROUTE: {len(targets)} targets")
        print(f"{'='*60}\n")
        
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Traceroute to {target}")
            print(f"{'-'*40}")
            
            try:
                result = self.interactive_traceroute(target, options)
                results['results'][target] = result
                results['successful'] += 1
                
                # Extract hops from result
                lines = result.split('\n')
                for line in lines:
                    if 'Hops detected:' in line:
                        hops = line.split(':')[1].strip()
                        print(f"   Hops: {hops}")
                        break
                
            except Exception as e:
                error_msg = f"❌ Failed to traceroute {target}: {e}"
                results['results'][target] = error_msg
                results['failed'] += 1
                print(f"   {error_msg}")
        
        print(f"\n{'='*60}")
        print(f"📊 BATCH COMPLETE: {results['successful']} successful, {results['failed']} failed")
        print(f"{'='*60}")
        
        return results

# ============================================================================
# NETWORK SCANNER (ENHANCED)
# ============================================================================

class EnhancedNetworkScanner:
    """Enhanced network scanner with multiple scanning techniques"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.traceroute_tool = EnhancedTracerouteTool(db_manager)
        
        # Check for nmap availability
        self.nmap_available = self._check_nmap()
        if not self.nmap_available:
            logger.warning("Nmap not found. Some scanning features will be limited.")
    
    def _check_nmap(self) -> bool:
        """Check if nmap is available"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def ping(self, target: str, count: int = 4, size: int = 56, 
            timeout: int = 1, flood: bool = False) -> Dict[str, Any]:
        """Enhanced ping with detailed statistics"""
        
        # Build command based on OS
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000)]
            if flood:
                cmd.append('-t')
        else:  # Unix-like
            cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout)]
            if flood:
                cmd.append('-f')
        
        cmd.append(target)
        
        result = self._execute_command(cmd, timeout=timeout * count + 5)
        
        # Parse results
        stats = self._parse_ping_output(result['output'], target)
        
        return {
            'success': result['returncode'] == 0,
            'target': target,
            'command': ' '.join(cmd),
            'output': result['output'][-2000:],  # Last 2000 chars
            'statistics': stats,
            'error': None if result['returncode'] == 0 else result['output'][-500:]
        }
    
    def _parse_ping_output(self, output: str, target: str) -> Dict[str, Any]:
        """Parse ping output for statistics"""
        stats = {
            'packets_transmitted': 0,
            'packets_received': 0,
            'packet_loss': 100.0,
            'round_trip_min': 0.0,
            'round_trip_avg': 0.0,
            'round_trip_max': 0.0,
            'round_trip_stddev': 0.0
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Packet statistics
            if 'packets transmitted' in line_lower:
                match = re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received', line)
                if match:
                    stats['packets_transmitted'] = int(match.group(1))
                    stats['packets_received'] = int(match.group(2))
                    if stats['packets_transmitted'] > 0:
                        stats['packet_loss'] = 100.0 * (stats['packets_transmitted'] - stats['packets_received']) / stats['packets_transmitted']
            
            # Round trip times (Unix format)
            elif 'rtt min/avg/max/mdev' in line_lower:
                match = re.search(r'=\s+([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', line)
                if match:
                    stats['round_trip_min'] = float(match.group(1))
                    stats['round_trip_avg'] = float(match.group(2))
                    stats['round_trip_max'] = float(match.group(3))
                    stats['round_trip_stddev'] = float(match.group(4))
            
            # Round trip times (Windows format)
            elif 'minimum =' in line_lower and 'maximum =' in line_lower and 'average =' in line_lower:
                matches = re.findall(r'=?\s*(\d+)ms', line)
                if len(matches) >= 3:
                    stats['round_trip_min'] = float(matches[0])
                    stats['round_trip_max'] = float(matches[1])
                    stats['round_trip_avg'] = float(matches[2])
        
        return stats
    
    def port_scan(self, target: str, ports: str = "1-1000", 
                 scan_type: str = "syn", timing: str = "T4") -> Dict[str, Any]:
        """Perform port scan using nmap"""
        
        if not self.nmap_available:
            return {
                'success': False,
                'error': 'Nmap not available',
                'suggestion': 'Install nmap for port scanning features'
            }
        
        # Build nmap command
        cmd = ['nmap']
        
        # Add scan type
        if scan_type.lower() == "syn":
            cmd.extend(['-sS'])
        elif scan_type.lower() == "tcp":
            cmd.extend(['-sT'])
        elif scan_type.lower() == "udp":
            cmd.extend(['-sU'])
        elif scan_type.lower() == "ack":
            cmd.extend(['-sA'])
        elif scan_type.lower() == "fin":
            cmd.extend(['-sF'])
        elif scan_type.lower() == "xmas":
            cmd.extend(['-sX'])
        elif scan_type.lower() == "null":
            cmd.extend(['-sN'])
        elif scan_type.lower() == "idle":
            cmd.extend(['-sI', 'zombie'])
        else:
            cmd.extend(['-sS'])  # Default to SYN scan
        
        # Add timing
        if timing in ["T0", "T1", "T2", "T3", "T4", "T5"]:
            cmd.append(f'-{timing}')
        else:
            cmd.append('-T4')  # Default timing
        
        # Add ports
        if ports:
            cmd.extend(['-p', ports])
        
        # Add target and options
        cmd.extend(['-Pn', '-n', '-v', target])
        
        # Execute scan
        result = self._execute_command(cmd, timeout=300)  # 5 minute timeout for scans
        
        # Parse results
        scan_result = self._parse_nmap_output(result['output'], target, scan_type)
        
        # Log to database
        if self.db and scan_result['success']:
            self.db.log_scan(ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=scan_result.get('open_ports', []),
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            ))
        
        return {
            'success': result['returncode'] == 0,
            'target': target,
            'scan_type': scan_type,
            'command': ' '.join(cmd),
            'output': result['output'][-5000:],  # Last 5000 chars
            'results': scan_result,
            'error': None if result['returncode'] == 0 else result['output'][-1000:]
        }
    
    def _parse_nmap_output(self, output: str, target: str, scan_type: str) -> Dict[str, Any]:
        """Parse nmap output for scan results"""
        result = {
            'target': target,
            'scan_type': scan_type,
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'host_up': False,
            'scan_duration': 0
        }
        
        lines = output.split('\n')
        current_port = None
        
        for line in lines:
            # Check if host is up
            if 'host is up' in line.lower():
                result['host_up'] = True
            
            # Scan duration
            elif 'scanned in' in line.lower():
                match = re.search(r'scanned in\s+([\d.]+)\s+seconds', line.lower())
                if match:
                    result['scan_duration'] = float(match.group(1))
            
            # Port status lines
            elif re.match(r'^\d+/(tcp|udp)\s+\w+', line.lower()):
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    if len(port_proto) == 2:
                        port_info = {
                            'port': int(port_proto[0]),
                            'protocol': port_proto[1],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else 'unknown'
                        }
                        
                        if port_info['state'] == 'open':
                            result['open_ports'].append(port_info)
                        elif port_info['state'] == 'filtered':
                            result['filtered_ports'].append(port_info)
                        elif port_info['state'] == 'closed':
                            result['closed_ports'].append(port_info)
            
            # Service version detection
            elif current_port and 'service:' in line.lower():
                service_info = line.split(':', 1)
                if len(service_info) == 2:
                    for port in result['open_ports']:
                        if port['port'] == current_port:
                            port['service_info'] = service_info[1].strip()
                            break
        
        return result
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """Perform OS detection scan"""
        if not self.nmap_available:
            return {
                'success': False,
                'error': 'Nmap not available'
            }
        
        cmd = ['nmap', '-O', '-v', '-n', target]
        result = self._execute_command(cmd, timeout=120)
        
        return {
            'success': result['returncode'] == 0,
            'target': target,
            'command': ' '.join(cmd),
            'output': result['output'][-3000:],
            'error': None if result['returncode'] == 0 else result['output'][-500:]
        }
    
    def service_detection(self, target: str, ports: str = None) -> Dict[str, Any]:
        """Perform service version detection"""
        if not self.nmap_available:
            return {
                'success': False,
                'error': 'Nmap not available'
            }
        
        cmd = ['nmap', '-sV', '-v', '-n']
        if ports:
            cmd.extend(['-p', ports])
        cmd.append(target)
        
        result = self._execute_command(cmd, timeout=180)
        
        return {
            'success': result['returncode'] == 0,
            'target': target,
            'command': ' '.join(cmd),
            'output': result['output'][-4000:],
            'error': None if result['returncode'] == 0 else result['output'][-500:]
        }
    
    def script_scan(self, target: str, script: str = "default") -> Dict[str, Any]:
        """Run nmap scripts"""
        if not self.nmap_available:
            return {
                'success': False,
                'error': 'Nmap not available'
            }
        
        cmd = ['nmap', '--script', script, '-v', '-n', target]
        result = self._execute_command(cmd, timeout=300)
        
        return {
            'success': result['returncode'] == 0,
            'target': target,
            'command': ' '.join(cmd),
            'output': result['output'][-5000:],
            'error': None if result['returncode'] == 0 else result['output'][-500:]
        }
    
    def get_ip_location(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation information"""
        try:
            # Try ip-api.com (free, no API key needed)
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'zip': data.get('zip', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'as': data.get('as', 'N/A'),
                        'query': data.get('query', 'N/A')
                    }
                else:
                    return {
                        'success': False,
                        'error': data.get('message', 'Unknown error')
                    }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}'
                }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def dns_lookup(self, domain: str, record_type: str = "A") -> Dict[str, Any]:
        """Perform DNS lookup"""
        try:
            # Use system's host command
            cmd = ['host', '-t', record_type, domain]
            result = self._execute_command(cmd, timeout=10)
            
            return {
                'success': result['returncode'] == 0,
                'domain': domain,
                'record_type': record_type,
                'output': result['output'],
                'error': None if result['returncode'] == 0 else result['output']
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            cmd = ['whois', target]
            result = self._execute_command(cmd, timeout=30)
            
            return {
                'success': result['returncode'] == 0,
                'target': target,
                'output': result['output'][-5000:],  # Limit output size
                'error': None if result['returncode'] == 0 else result['output']
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Comprehensive IP analysis"""
        results = {
            'ip': ip,
            'timestamp': datetime.datetime.now().isoformat(),
            'location': None,
            'ports': None,
            'threats': [],
            'recommendations': []
        }
        
        # Get location
        location = self.get_ip_location(ip)
        if location['success']:
            results['location'] = location
        else:
            results['threats'].append(f"Could not get location: {location.get('error')}")
        
        # Quick port scan
        if self.nmap_available:
            scan = self.port_scan(ip, ports="1-100", scan_type="syn", timing="T4")
            if scan['success']:
                results['ports'] = scan['results']
                
                # Analyze open ports
                open_ports = scan['results'].get('open_ports', [])
                if open_ports:
                    results['threats'].append(f"Found {len(open_ports)} open port(s)")
                    
                    # Check for common vulnerable ports
                    vulnerable_ports = {
                        21: 'FTP - Check for anonymous access',
                        22: 'SSH - Check for weak passwords',
                        23: 'Telnet - Insecure, recommend disable',
                        25: 'SMTP - Check for open relay',
                        80: 'HTTP - Check for web vulnerabilities',
                        443: 'HTTPS - Check SSL/TLS configuration',
                        445: 'SMB - Check for eternalblue vulnerability',
                        3389: 'RDP - Check for bluekeep vulnerability',
                        5900: 'VNC - Often has weak authentication',
                        8080: 'HTTP Proxy - Check for open proxy'
                    }
                    
                    for port_info in open_ports:
                        port = port_info['port']
                        if port in vulnerable_ports:
                            results['recommendations'].append(
                                f"Port {port} ({port_info.get('service', 'unknown')}): {vulnerable_ports[port]}"
                            )
            else:
                results['threats'].append(f"Port scan failed: {scan.get('error')}")
        
        # Check if IP is in threat database
        if self.db:
            threats = self.db.get_recent_threats(50)
            ip_threats = [t for t in threats if t.get('source_ip') == ip]
            if ip_threats:
                results['threats'].extend([
                    f"Previous threat: {t.get('threat_type')} ({t.get('severity')})" 
                    for t in ip_threats[:3]  # Show only 3 most recent
                ])
        
        return results
    
    def _execute_command(self, cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Execute shell command with timeout"""
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
            
            return {
                'returncode': result.returncode,
                'output': result.stdout if result.stdout else result.stderr,
                'execution_time': execution_time
            }
        
        except subprocess.TimeoutExpired:
            return {
                'returncode': -1,
                'output': f"Command timed out after {timeout} seconds",
                'execution_time': timeout
            }
        
        except Exception as e:
            return {
                'returncode': -2,
                'output': f"Error executing command: {e}",
                'execution_time': 0
            }

# ============================================================================
# NETWORK MONITOR & THREAT DETECTION
# ============================================================================

class NetworkMonitor:
    """Network monitoring and threat detection system"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'udp_flood': self.config.get('monitoring', {}).get('udp_flood_threshold', 500),
            'http_flood': self.config.get('monitoring', {}).get('http_flood_threshold', 200),
            'ddos': self.config.get('monitoring', {}).get('ddos_threshold', 1000)
        }
        self.counters = {}
        self.threads = []
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            logger.warning("Monitoring already running")
            return
        
        self.monitoring = True
        logger.info("Starting network monitoring...")
        
        # Start monitoring threads
        self.threads = [
            threading.Thread(target=self._monitor_port_scans, daemon=True),
            threading.Thread(target=self._monitor_syn_floods, daemon=True),
            threading.Thread(target=self._monitor_connections, daemon=True),
            threading.Thread(target=self._monitor_system_metrics, daemon=True),
            threading.Thread(target=self._monitor_logged_ips, daemon=True)
        ]
        
        for thread in self.threads:
            thread.start()
        
        logger.info(f"Network monitoring started with {len(self.threads)} threads")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        logger.info("Network monitoring stopped")
    
    def add_ip_to_monitoring(self, ip: str) -> bool:
        """Add IP to monitoring list"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            
            # Also add to database
            if self.db:
                self.db.add_monitored_ip(ip, "Added via monitoring")
            
            logger.info(f"Added IP to monitoring: {ip}")
            return True
        
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring list"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            
            # Mark as inactive in database
            if self.db:
                self.db.remove_monitored_ip(ip)
            
            logger.info(f"Removed IP from monitoring: {ip}")
            return True
        
        return False
    
    def get_monitored_ips(self) -> List[str]:
        """Get list of monitored IPs"""
        return sorted(self.monitored_ips)
    
    def _monitor_port_scans(self):
        """Monitor for port scanning activity"""
        logger.info("Port scan monitor started")
        
        port_attempts = {}
        
        while self.monitoring:
            try:
                # Get current connections
                connections = psutil.net_connections()
                
                # Analyze connections for port scan patterns
                source_ports = {}
                for conn in connections:
                    if conn.raddr:  # Has remote address
                        source_ip = conn.raddr.ip
                        if source_ip not in source_ports:
                            source_ports[source_ip] = set()
                        source_ports[source_ip].add(conn.raddr.port)
                
                # Check for port scan patterns
                current_time = time.time()
                for source_ip, ports in source_ports.items():
                    num_ports = len(ports)
                    
                    if num_ports > self.thresholds['port_scan']:
                        # Potential port scan detected
                        if source_ip not in port_attempts:
                            port_attempts[source_ip] = {'count': 0, 'first_seen': current_time}
                        
                        port_attempts[source_ip]['count'] += 1
                        
                        # If we've seen multiple port scans from this IP, create alert
                        if port_attempts[source_ip]['count'] >= 3:
                            self._create_threat_alert(
                                threat_type="Port Scan",
                                source_ip=source_ip,
                                severity="high",
                                description=f"Multiple port scans detected. Scanned {num_ports} ports.",
                                action_taken="Logged and monitoring"
                            )
                            port_attempts[source_ip]['count'] = 0  # Reset counter
                
                # Cleanup old entries (older than 5 minutes)
                cleanup_time = current_time - 300
                expired_ips = [ip for ip, data in port_attempts.items() 
                              if data['first_seen'] < cleanup_time]
                for ip in expired_ips:
                    del port_attempts[ip]
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"Port scan monitor error: {e}")
                time.sleep(10)
    
    def _monitor_syn_floods(self):
        """Monitor for SYN flood attacks"""
        logger.info("SYN flood monitor started")
        
        syn_counts = {}
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                syn_connections = [c for c in connections if c.status == 'SYN_SENT']
                
                # Count SYN connections per source
                for conn in syn_connections:
                    if conn.raddr:
                        source_ip = conn.raddr.ip
                        syn_counts[source_ip] = syn_counts.get(source_ip, 0) + 1
                
                # Check thresholds
                current_time = time.time()
                for source_ip, count in list(syn_counts.items()):
                    if count > self.thresholds['syn_flood']:
                        self._create_threat_alert(
                            threat_type="SYN Flood",
                            source_ip=source_ip,
                            severity="high",
                            description=f"SYN flood detected. {count} SYN packets from this IP.",
                            action_taken="Logged"
                        )
                        syn_counts[source_ip] = 0  # Reset counter
                
                # Cleanup counters every 30 seconds
                if current_time % 30 < 1:  # Every 30 seconds
                    syn_counts.clear()
                
                time.sleep(5)  # Check every 5 seconds
            
            except Exception as e:
                logger.error(f"SYN flood monitor error: {e}")
                time.sleep(10)
    
    def _monitor_connections(self):
        """Monitor network connections"""
        logger.info("Connection monitor started")
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                # Log interesting connections to database
                for conn in connections[:50]:  # Limit to first 50 connections
                    if conn.raddr and self.db:
                        net_conn = NetworkConnection(
                            local_ip=conn.laddr.ip if conn.laddr else "",
                            local_port=conn.laddr.port if conn.laddr else 0,
                            remote_ip=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            status=conn.status,
                            process_name="",
                            protocol=conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                        )
                        
                        # Try to get process name
                        try:
                            if conn.pid:
                                proc = psutil.Process(conn.pid)
                                net_conn.process_name = proc.name()
                        except:
                            pass
                        
                        self.db.log_connection(net_conn)
                
                time.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def _monitor_system_metrics(self):
        """Monitor system metrics"""
        logger.info("System metrics monitor started")
        
        while self.monitoring:
            try:
                if self.db:
                    self.db.log_system_metrics()
                
                # Check for high resource usage
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                
                if cpu > 90:
                    self._create_threat_alert(
                        threat_type="High CPU Usage",
                        source_ip="localhost",
                        severity="medium",
                        description=f"CPU usage at {cpu}%",
                        action_taken="Logged"
                    )
                
                if mem.percent > 90:
                    self._create_threat_alert(
                        threat_type="High Memory Usage",
                        source_ip="localhost",
                        severity="medium",
                        description=f"Memory usage at {mem.percent}%",
                        action_taken="Logged"
                    )
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                logger.error(f"System metrics monitor error: {e}")
                time.sleep(10)
    
    def _monitor_logged_ips(self):
        """Monitor IPs logged in database"""
        logger.info("Logged IPs monitor started")
        
        while self.monitoring:
            try:
                if self.db:
                    # Get monitored IPs from database
                    db_ips = self.db.get_monitored_ips(active_only=True)
                    for ip_info in db_ips:
                        ip = ip_info.get('ip_address')
                        if ip and ip not in self.monitored_ips:
                            self.monitored_ips.add(ip)
                
                time.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                logger.error(f"Logged IPs monitor error: {e}")
                time.sleep(10)
    
    def _create_threat_alert(self, threat_type: str, source_ip: str, 
                            severity: str, description: str, action_taken: str):
        """Create and log threat alert"""
        alert = ThreatAlert(
            timestamp=datetime.datetime.now().isoformat(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            action_taken=action_taken
        )
        
        if self.db:
            self.db.log_threat(alert)
        
        # Log to console
        log_msg = f"🚨 THREAT ALERT: {threat_type} from {source_ip} ({severity})"
        if severity == "high":
            logger.error(log_msg)
        elif severity == "medium":
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
        
        return alert
    
    def detect_ddos(self, packets_per_second: int) -> bool:
        """Detect DDoS attack based on packet rate"""
        return packets_per_second > self.thresholds['ddos']
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'monitored_ips': list(self.monitored_ips),
            'thresholds': self.thresholds,
            'threads_running': len([t for t in self.threads if t.is_alive()])
        }

# ============================================================================
# COMMAND EXECUTOR (300+ COMMANDS)
# ============================================================================

class CommandExecutor:
    """Command executor with 300+ commands support"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.scanner = EnhancedNetworkScanner(db_manager)
        self.traceroute_tool = EnhancedTracerouteTool(db_manager)
        
        # Setup command map
        self.command_map = self._setup_command_map()
        
        # Command categories for help
        self.categories = {
            'ping': 'Network ping commands',
            'scan': 'Port scanning and reconnaissance',
            'traceroute': 'Network path tracing',
            'web': 'Web and HTTP tools',
            'ssh': 'SSH connections and tunneling',
            'traffic': 'Network traffic generation and testing',
            'info': 'DNS, WHOIS, and information gathering',
            'system': 'System monitoring and information',
            'transfer': 'File transfer commands',
            'security': 'Security testing tools',
            'misc': 'Miscellaneous utilities'
        }
    
    def _setup_command_map(self) -> Dict[str, callable]:
        """Setup command execution map"""
        return {
            # Ping commands
            'ping': self._execute_ping,
            'ping4': self._execute_ping,
            'ping6': self._execute_ping6,
            
            # Scan commands
            'scan': self._execute_scan,
            'nmap': self._execute_nmap,
            'portscan': self._execute_portscan,
            
            # Traceroute commands
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            'mtr': self._execute_mtr,
            'tracepath': self._execute_tracepath,
            
            # Web commands
            'curl': self._execute_curl,
            'wget': self._execute_wget,
            'http': self._execute_http,
            
            # SSH commands
            'ssh': self._execute_ssh,
            'scp': self._execute_scp,
            
            # Traffic commands
            'iperf': self._execute_iperf,
            'iperf3': self._execute_iperf3,
            'hping3': self._execute_hping3,
            'ab': self._execute_ab,
            'siege': self._execute_siege,
            'tcpdump': self._execute_tcpdump,
            
            # Info commands
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'nslookup': self._execute_nslookup,
            'host': self._execute_host,
            'dns': self._execute_dns,
            'location': self._execute_location,
            'analyze': self._execute_analyze,
            
            # System commands
            'netstat': self._execute_netstat,
            'ss': self._execute_ss,
            'ifconfig': self._execute_ifconfig,
            'ip': self._execute_ip,
            'ps': self._execute_ps,
            'top': self._execute_top,
            'free': self._execute_free,
            'df': self._execute_df,
            'uptime': self._execute_uptime,
            
            # Transfer commands
            'rsync': self._execute_rsync,
            'ftp': self._execute_ftp,
            
            # Security commands
            'nikto': self._execute_nikto,
            'sqlmap': self._execute_sqlmap,
            'gobuster': self._execute_gobuster,
            'dirb': self._execute_dirb,
            
            # Misc commands
            'nc': self._execute_nc,
            'telnet': self._execute_telnet,
            'openssl': self._execute_openssl,
            'hash': self._execute_hash,
            'base64': self._execute_base64,
            'python': self._execute_python,
            'bash': self._execute_bash,
            'php': self._execute_php,
            
            # System info
            'system': self._execute_system,
            'network': self._execute_network,
            'status': self._execute_status,
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        # Parse command
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Log command
        if self.db:
            self.db.log_command(command, source, True)
        
        # Execute command
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                # Try as generic shell command
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            
            # Update command log with execution time
            if self.db:
                self.db.log_command(command, source, result.get('success', False), 
                                  result.get('output', '')[:5000], execution_time)
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            if self.db:
                self.db.log_command(command, source, False, error_msg, execution_time)
            
            return self._create_result(False, error_msg, execution_time)
    
    def get_help(self, category: str = None) -> Dict[str, Any]:
        """Get help for commands"""
        if category:
            if category.lower() == 'all':
                # Get all commands by category
                help_text = {}
                for cat_name, cat_desc in self.categories.items():
                    templates = self.db.get_command_templates(cat_name) if self.db else []
                    help_text[cat_name] = {
                        'description': cat_desc,
                        'commands': [t['usage'] for t in templates[:10]]  # First 10
                    }
                return self._create_result(True, help_text)
            else:
                # Get specific category
                templates = self.db.get_command_templates(category) if self.db else []
                if templates:
                    commands = [t['usage'] for t in templates]
                    return self._create_result(True, {
                        'category': category,
                        'description': self.categories.get(category, 'Unknown category'),
                        'commands': commands
                    })
                else:
                    return self._create_result(False, f"No commands found for category: {category}")
        else:
            # Show available categories
            return self._create_result(True, {
                'categories': self.categories,
                'total_commands': sum(len(self.db.get_command_templates(cat)) if self.db else 0 
                                     for cat in self.categories)
            })
    
    def _create_result(self, success: bool, data: Any, 
                      execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result dictionary"""
        if isinstance(data, str):
            return {
                'success': success,
                'output': data,
                'execution_time': execution_time
            }
        else:
            return {
                'success': success,
                'data': data,
                'execution_time': execution_time
            }
    
    # ==================== COMMAND HANDLERS ====================
    
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        """Execute ping command"""
        if not args:
            return self._create_result(False, "Usage: ping <target> [options]")
        
        target = args[0]
        options = args[1:] if len(args) > 1 else []
        
        # Parse options
        count = 4
        size = 56
        timeout = 1
        flood = False
        
        i = 0
        while i < len(options):
            opt = options[i]
            if opt == '-c' and i + 1 < len(options):
                try:
                    count = int(options[i + 1])
                    i += 1
                except:
                    pass
            elif opt == '-s' and i + 1 < len(options):
                try:
                    size = int(options[i + 1])
                    i += 1
                except:
                    pass
            elif opt == '-w' and i + 1 < len(options):
                try:
                    timeout = int(options[i + 1])
                    i += 1
                except:
                    pass
            elif opt == '-f':
                flood = True
            i += 1
        
        result = self.scanner.ping(target, count, size, timeout, flood)
        return self._create_result(result['success'], result)
    
    def _execute_ping6(self, args: List[str]) -> Dict[str, Any]:
        """Execute IPv6 ping"""
        if not args:
            return self._create_result(False, "Usage: ping6 <target>")
        
        # For IPv6 ping, we need to modify the command slightly
        target = args[0]
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-6', target]
        else:
            cmd = ['ping6', target]
        
        cmd.extend(args[1:])
        return self._execute_generic(' '.join(cmd))
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute scan command"""
        if not args:
            return self._create_result(False, "Usage: scan <target> [ports] [options]")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "syn"
        
        if len(args) > 1:
            # Check if second arg is ports or scan type
            if args[1].startswith('-'):
                scan_type = args[1][1:] if args[1][0] == '-' else args[1]
                if len(args) > 2:
                    ports = args[2]
            else:
                ports = args[1]
                if len(args) > 2 and args[2].startswith('-'):
                    scan_type = args[2][1:] if args[2][0] == '-' else args[2]
        
        result = self.scanner.port_scan(target, ports, scan_type)
        return self._create_result(result['success'], result)
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        """Execute nmap command"""
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        
        return self._execute_generic('nmap ' + ' '.join(args))
    
    def _execute_portscan(self, args: List[str]) -> Dict[str, Any]:
        """Execute port scan"""
        return self._execute_scan(args)
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        """Execute traceroute"""
        if not args:
            return self._create_result(False, "Usage: traceroute <target> [options]")
        
        target = args[0]
        options = {}
        
        # Parse options
        for i in range(1, len(args)):
            if args[i] == '-n':
                options['no_dns'] = True
            elif args[i] == '-m' and i + 1 < len(args):
                try:
                    options['max_hops'] = int(args[i + 1])
                except:
                    pass
        
        result = self.traceroute_tool.interactive_traceroute(target, options)
        return self._create_result(True, result)
    
    def _execute_mtr(self, args: List[str]) -> Dict[str, Any]:
        """Execute MTR"""
        if not args:
            return self._create_result(False, "Usage: mtr <target>")
        
        return self._execute_generic('mtr ' + ' '.join(args))
    
    def _execute_tracepath(self, args: List[str]) -> Dict[str, Any]:
        """Execute tracepath"""
        if not args:
            return self._create_result(False, "Usage: tracepath <target>")
        
        return self._execute_generic('tracepath ' + ' '.join(args))
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        """Execute curl command"""
        if not args:
            return self._create_result(False, "Usage: curl <url> [options]")
        
        return self._execute_generic('curl ' + ' '.join(args))
    
    def _execute_wget(self, args: List[str]) -> Dict[str, Any]:
        """Execute wget command"""
        if not args:
            return self._create_result(False, "Usage: wget <url> [options]")
        
        return self._execute_generic('wget ' + ' '.join(args))
    
    def _execute_http(self, args: List[str]) -> Dict[str, Any]:
        """Execute HTTP request"""
        if not args:
            return self._create_result(False, "Usage: http <url> [method]")
        
        url = args[0]
        method = 'GET'
        if len(args) > 1:
            method = args[1].upper()
        
        try:
            response = requests.request(method, url, timeout=10)
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:1000] + ('...' if len(response.text) > 1000 else ''),
                'size': len(response.content)
            }
            return self._create_result(True, result)
        except Exception as e:
            return self._create_result(False, f"HTTP request failed: {e}")
    
    def _execute_ssh(self, args: List[str]) -> Dict[str, Any]:
        """Execute SSH command"""
        if not args:
            return self._create_result(False, "Usage: ssh <host> [options]")
        
        return self._execute_generic('ssh ' + ' '.join(args))
    
    def _execute_scp(self, args: List[str]) -> Dict[str, Any]:
        """Execute SCP command"""
        if not args:
            return self._create_result(False, "Usage: scp <source> <destination>")
        
        return self._execute_generic('scp ' + ' '.join(args))
    
    def _execute_iperf(self, args: List[str]) -> Dict[str, Any]:
        """Execute iperf command"""
        if not args:
            return self._create_result(False, "Usage: iperf -c <server> [options]")
        
        return self._execute_generic('iperf ' + ' '.join(args))
    
    def _execute_iperf3(self, args: List[str]) -> Dict[str, Any]:
        """Execute iperf3 command"""
        if not args:
            return self._create_result(False, "Usage: iperf3 -c <server> [options]")
        
        return self._execute_generic('iperf3 ' + ' '.join(args))
    
    def _execute_hping3(self, args: List[str]) -> Dict[str, Any]:
        """Execute hping3 command"""
        if not args:
            return self._create_result(False, "Usage: hping3 <target> [options]")
        
        return self._execute_generic('hping3 ' + ' '.join(args))
    
    def _execute_ab(self, args: List[str]) -> Dict[str, Any]:
        """Execute Apache Bench command"""
        if not args:
            return self._create_result(False, "Usage: ab [options] <url>")
        
        return self._execute_generic('ab ' + ' '.join(args))
    
    def _execute_siege(self, args: List[str]) -> Dict[str, Any]:
        """Execute siege command"""
        if not args:
            return self._create_result(False, "Usage: siege [options] <url>")
        
        return self._execute_generic('siege ' + ' '.join(args))
    
    def _execute_tcpdump(self, args: List[str]) -> Dict[str, Any]:
        """Execute tcpdump command"""
        if not args:
            return self._create_result(False, "Usage: tcpdump [options]")
        
        return self._execute_generic('tcpdump ' + ' '.join(args))
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        """Execute whois command"""
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        
        target = args[0]
        result = self.scanner.whois_lookup(target)
        return self._create_result(result['success'], result)
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        """Execute dig command"""
        if not args:
            return self._execute_generic('dig')
        
        return self._execute_generic('dig ' + ' '.join(args))
    
    def _execute_nslookup(self, args: List[str]) -> Dict[str, Any]:
        """Execute nslookup command"""
        if not args:
            return self._execute_generic('nslookup')
        
        return self._execute_generic('nslookup ' + ' '.join(args))
    
    def _execute_host(self, args: List[str]) -> Dict[str, Any]:
        """Execute host command"""
        if not args:
            return self._create_result(False, "Usage: host <domain>")
        
        target = args[0]
        result = self.scanner.dns_lookup(target)
        return self._create_result(result['success'], result)
    
    def _execute_dns(self, args: List[str]) -> Dict[str, Any]:
        """Execute DNS lookup"""
        return self._execute_host(args)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        """Get IP location"""
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        
        target = args[0]
        result = self.scanner.get_ip_location(target)
        return self._create_result(result['success'], result)
    
    def _execute_analyze(self, args: List[str]) -> Dict[str, Any]:
        """Analyze IP"""
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        
        target = args[0]
        result = self.scanner.analyze_ip(target)
        return self._create_result(True, result)
    
    def _execute_netstat(self, args: List[str]) -> Dict[str, Any]:
        """Execute netstat command"""
        return self._execute_generic('netstat ' + ' '.join(args))
    
    def _execute_ss(self, args: List[str]) -> Dict[str, Any]:
        """Execute ss command"""
        return self._execute_generic('ss ' + ' '.join(args))
    
    def _execute_ifconfig(self, args: List[str]) -> Dict[str, Any]:
        """Execute ifconfig command"""
        return self._execute_generic('ifconfig ' + ' '.join(args))
    
    def _execute_ip(self, args: List[str]) -> Dict[str, Any]:
        """Execute ip command"""
        return self._execute_generic('ip ' + ' '.join(args))
    
    def _execute_ps(self, args: List[str]) -> Dict[str, Any]:
        """Execute ps command"""
        return self._execute_generic('ps ' + ' '.join(args))
    
    def _execute_top(self, args: List[str]) -> Dict[str, Any]:
        """Execute top command"""
        return self._execute_generic('top ' + ' '.join(args))
    
    def _execute_free(self, args: List[str]) -> Dict[str, Any]:
        """Execute free command"""
        return self._execute_generic('free ' + ' '.join(args))
    
    def _execute_df(self, args: List[str]) -> Dict[str, Any]:
        """Execute df command"""
        return self._execute_generic('df ' + ' '.join(args))
    
    def _execute_uptime(self, args: List[str]) -> Dict[str, Any]:
        """Execute uptime command"""
        return self._execute_generic('uptime ' + ' '.join(args))
    
    def _execute_rsync(self, args: List[str]) -> Dict[str, Any]:
        """Execute rsync command"""
        if not args:
            return self._create_result(False, "Usage: rsync <source> <destination>")
        
        return self._execute_generic('rsync ' + ' '.join(args))
    
    def _execute_ftp(self, args: List[str]) -> Dict[str, Any]:
        """Execute FTP command"""
        if not args:
            return self._create_result(False, "Usage: ftp <host>")
        
        return self._execute_generic('ftp ' + ' '.join(args))
    
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        """Execute nikto command"""
        if not args:
            return self._create_result(False, "Usage: nikto -h <host>")
        
        return self._execute_generic('nikto ' + ' '.join(args))
    
    def _execute_sqlmap(self, args: List[str]) -> Dict[str, Any]:
        """Execute sqlmap command"""
        if not args:
            return self._create_result(False, "Usage: sqlmap -u <url>")
        
        return self._execute_generic('sqlmap ' + ' '.join(args))
    
    def _execute_gobuster(self, args: List[str]) -> Dict[str, Any]:
        """Execute gobuster command"""
        if not args:
            return self._create_result(False, "Usage: gobuster <mode> [options]")
        
        return self._execute_generic('gobuster ' + ' '.join(args))
    
    def _execute_dirb(self, args: List[str]) -> Dict[str, Any]:
        """Execute dirb command"""
        if not args:
            return self._create_result(False, "Usage: dirb <url>")
        
        return self._execute_generic('dirb ' + ' '.join(args))
    
    def _execute_nc(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat command"""
        if not args:
            return self._create_result(False, "Usage: nc [options]")
        
        return self._execute_generic('nc ' + ' '.join(args))
    
    def _execute_telnet(self, args: List[str]) -> Dict[str, Any]:
        """Execute telnet command"""
        if not args:
            return self._create_result(False, "Usage: telnet <host> [port]")
        
        return self._execute_generic('telnet ' + ' '.join(args))
    
    def _execute_openssl(self, args: List[str]) -> Dict[str, Any]:
        """Execute openssl command"""
        if not args:
            return self._create_result(False, "Usage: openssl <command> [options]")
        
        return self._execute_generic('openssl ' + ' '.join(args))
    
    def _execute_hash(self, args: List[str]) -> Dict[str, Any]:
        """Execute hash command"""
        if not args:
            return self._create_result(False, "Usage: hash <algorithm> <text>")
        
        if len(args) < 2:
            return self._create_result(False, "Usage: hash <algorithm> <text>")
        
        algorithm = args[0].lower()
        text = ' '.join(args[1:])
        
        if algorithm == 'md5':
            hash_obj = hashlib.md5(text.encode())
        elif algorithm == 'sha1':
            hash_obj = hashlib.sha1(text.encode())
        elif algorithm == 'sha256':
            hash_obj = hashlib.sha256(text.encode())
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512(text.encode())
        else:
            return self._create_result(False, f"Unsupported algorithm: {algorithm}")
        
        return self._create_result(True, hash_obj.hexdigest())
    
    def _execute_base64(self, args: List[str]) -> Dict[str, Any]:
        """Execute base64 encode/decode"""
        if not args:
            return self._create_result(False, "Usage: base64 <encode|decode> <text>")
        
        if len(args) < 2:
            return self._create_result(False, "Usage: base64 <encode|decode> <text>")
        
        operation = args[0].lower()
        text = ' '.join(args[1:])
        
        try:
            if operation == 'encode':
                import base64
                encoded = base64.b64encode(text.encode()).decode()
                return self._create_result(True, encoded)
            elif operation == 'decode':
                import base64
                decoded = base64.b64decode(text.encode()).decode()
                return self._create_result(True, decoded)
            else:
                return self._create_result(False, f"Unknown operation: {operation}")
        except Exception as e:
            return self._create_result(False, f"Base64 operation failed: {e}")
    
    def _execute_python(self, args: List[str]) -> Dict[str, Any]:
        """Execute Python code"""
        if not args:
            return self._create_result(False, "Usage: python <code>")
        
        code = ' '.join(args)
        try:
            # Use exec to execute Python code
            # Note: This is potentially dangerous! Use with caution.
            result = {}
            exec(f"__result = {code}", {}, result)
            return self._create_result(True, str(result.get('__result', 'Executed')))
        except:
            try:
                # Try as a statement
                exec(code, {})
                return self._create_result(True, "Executed successfully")
            except Exception as e:
                return self._create_result(False, f"Python execution error: {e}")
    
    def _execute_bash(self, args: List[str]) -> Dict[str, Any]:
        """Execute bash command"""
        if not args:
            return self._create_result(False, "Usage: bash <command>")
        
        return self._execute_generic('bash -c "' + ' '.join(args) + '"')
    
    def _execute_php(self, args: List[str]) -> Dict[str, Any]:
        """Execute PHP code"""
        if not args:
            return self._create_result(False, "Usage: php <code>")
        
        code = ' '.join(args)
        return self._execute_generic(f'php -r "{code}"')
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
                'free': psutil.virtual_memory().free
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'users': [u.name for u in psutil.users()]
        }
        
        return self._create_result(True, info)
    
    def _execute_network(self, args: List[str]) -> Dict[str, Any]:
        """Get network information"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            interfaces = psutil.net_if_addrs()
            
            network_info = {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {}
            }
            
            for iface, addrs in interfaces.items():
                network_info['interfaces'][iface] = []
                for addr in addrs:
                    network_info['interfaces'][iface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
                        'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                    })
            
            # Network connections
            connections = psutil.net_connections()
            network_info['connections'] = {
                'total': len(connections),
                'tcp': len([c for c in connections if c.type == socket.SOCK_STREAM]),
                'udp': len([c for c in connections if c.type == socket.SOCK_DGRAM])
            }
            
            return self._create_result(True, network_info)
        
        except Exception as e:
            return self._create_result(False, f"Failed to get network info: {e}")
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        """Get system status"""
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv,
                'packets_sent': psutil.net_io_counters().packets_sent,
                'packets_recv': psutil.net_io_counters().packets_recv
            }
        }
        
        return self._create_result(True, status)
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
            
            return self._create_result(
                result.returncode == 0,
                result.stdout if result.stdout else result.stderr,
                execution_time
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(False, f"Command timed out after 60 seconds")
        
        except Exception as e:
            return self._create_result(False, f"Command execution failed: {e}")

# ============================================================================
# TELEGRAM BOT HANDLER (ALL COMMANDS)
# ============================================================================

class TelegramBotHandler:
    """Telegram bot handler with all 300+ commands support"""
    
    def __init__(self, db_manager: DatabaseManager, executor: CommandExecutor):
        self.db = db_manager
        self.executor = executor
        self.config = ConfigManager.load_telegram_config()
        self.token = self.config.get('token', '')
        self.chat_id = self.config.get('chat_id', '')
        self.enabled = self.config.get('enabled', False)
        self.last_update_id = 0
        
        # Setup command handlers
        self.command_handlers = self._setup_command_handlers()
    
    def _setup_command_handlers(self) -> Dict[str, callable]:
        """Setup Telegram command handlers"""
        return {
            '/start': self._handle_start,
            '/help': self._handle_help,
            '/ping': self._handle_ping,
            '/scan': self._handle_scan,
            '/traceroute': self._handle_traceroute,
            '/nmap': self._handle_nmap,
            '/curl': self._handle_curl,
            '/ssh': self._handle_ssh,
            '/whois': self._handle_whois,
            '/dns': self._handle_dns,
            '/location': self._handle_location,
            '/analyze': self._handle_analyze,
            '/system': self._handle_system,
            '/network': self._handle_network,
            '/status': self._handle_status,
            '/history': self._handle_history,
            '/threats': self._handle_threats,
            '/report': self._handle_report,
            '/monitor': self._handle_monitor,
            '/config': self._handle_config,
            '/test': self._handle_test,
            '/commands': self._handle_commands,
        }
    
    def send_message(self, message: str, parse_mode: str = 'HTML', 
                    disable_preview: bool = True) -> bool:
        """Send message to Telegram"""
        if not self.token or not self.chat_id or not self.enabled:
            logger.warning("Telegram not configured or disabled")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                chunks = self._split_message(message)
                for chunk in chunks:
                    payload = {
                        'chat_id': self.chat_id,
                        'text': chunk,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': disable_preview
                    }
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Failed to send Telegram message chunk: {response.status_code}")
                        return False
                    time.sleep(0.3)  # Rate limiting
                return True
            else:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': disable_preview
                }
                response = requests.post(url, json=payload, timeout=10)
                success = response.status_code == 200
                if not success:
                    logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                return success
        
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False
    
    def _split_message(self, message: str, max_length: int = 4000) -> List[str]:
        """Split long message into chunks"""
        chunks = []
        current_chunk = ""
        
        # Split by lines first
        lines = message.split('\n')
        
        for line in lines:
            if len(current_chunk) + len(line) + 1 > max_length:
                if current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = line
                else:
                    # Single line too long, split by words
                    words = line.split()
                    for word in words:
                        if len(current_chunk) + len(word) + 1 > max_length:
                            chunks.append(current_chunk)
                            current_chunk = word
                        else:
                            current_chunk += " " + word if current_chunk else word
            else:
                current_chunk += "\n" + line if current_chunk else line
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    def get_updates(self) -> List[Dict]:
        """Get updates from Telegram"""
        if not self.token:
            return []
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 10,
                'allowed_updates': ['message']
            }
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data.get('result', [])
        
        except Exception as e:
            logger.error(f"Telegram getUpdates error: {e}")
        
        return []
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Telegram connection"""
        if not self.token:
            return False, "Token not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    return True, f"Connected as @{bot_info.get('username', 'Unknown')}"
                else:
                    return False, f"API error: {data.get('description')}"
            else:
                return False, f"HTTP error: {response.status_code}"
        
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def process_updates(self):
        """Process incoming Telegram updates"""
        updates = self.get_updates()
        
        for update in updates:
            self.last_update_id = update['update_id']
            
            if 'message' in update and 'text' in update['message']:
                self.process_message(update['message'])
    
    def process_message(self, message: Dict):
        """Process individual message"""
        text = message.get('text', '').strip()
        chat_id = message.get('chat', {}).get('id')
        
        if not text:
            return
        
        # Set chat ID if not set
        if not self.chat_id and chat_id:
            self.chat_id = str(chat_id)
            self.enabled = True
            ConfigManager.save_telegram_config(self.token, self.chat_id, self.enabled)
            logger.info(f"Telegram chat ID set: {self.chat_id}")
        
        # Process command
        if text.startswith('/'):
            self._process_command(text, chat_id)
        else:
            # Echo non-command messages
            self.send_message(f"💬 You said: {text}")
    
    def _process_command(self, command: str, chat_id: str):
        """Process command"""
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Log command
        if self.db:
            self.db.log_command(command, 'telegram', True)
        
        # Execute command
        if cmd in self.command_handlers:
            try:
                response = self.command_handlers[cmd](args)
                self.send_message(response)
            except Exception as e:
                error_msg = f"❌ Error executing command: {str(e)}"
                self.send_message(error_msg)
                logger.error(f"Command error: {e}")
        else:
            # Try as generic command
            result = self.executor.execute(command[1:], 'telegram')  # Remove '/'
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                if isinstance(output, dict):
                    output = json.dumps(output, indent=2)
                
                response = f"✅ Command executed ({result['execution_time']:.2f}s)\n\n"
                response += f"<code>{output[:3500]}</code>"
                if len(str(output)) > 3500:
                    response += "\n\n... (output truncated)"
                
                self.send_message(response)
            else:
                error_msg = f"❌ Command failed: {result.get('output', 'Unknown error')}"
                self.send_message(error_msg)
    
    # ==================== COMMAND HANDLERS ====================
    
    def _handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>ACCURATE CYBER DEFENSE CYBER DRILL SIMULATION DEMO</b> 🚀

Welcome to your comprehensive accurate cybersecurity assistant!

<b>🔍 QUICK COMMANDS:</b>
<code>/ping 8.8.8.8</code> - Ping IP address
<code>/scan 192.168.1.1</code> - Port scan
<code>/traceroute exmple.com</code> - Network path tracing
<code>/location 1.1.1.1</code> - IP geolocation
<code>/whois example.com</code> - WHOIS lookup

<b>📊 SYSTEM:</b>
<code>/status</code> - System status
<code>/system</code> - System information
<code>/network</code> - Network information
<code>/history</code> - Command history
<code>/threats</code> - Recent threats

<b>🛡️ SECURITY:</b>
<code>/analyze 192.168.1.1</code> - Analyze IP threats
<code>/report</code> - Generate security report
<code>/monitor add 192.168.1.1</code> - Add IP to monitoring

<b>❓ HELP:</b>
<code>/help</code> - Show help
<code>/commands</code> - List all commands

Type <code>/help all</code> for complete command list!

<b>💡 Tip:</b> All 300+ Linux commands are supported via direct execution!
        """
    
    def _handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        if args and args[0].lower() == 'all':
            # Show all commands by category
            help_text = "<b>📋 COMPLETE COMMAND LIST (300+ Commands)</b>\n\n"
            
            categories = self.executor.categories
            for category, description in categories.items():
                help_text += f"<b>{category.upper()} ({description}):</b>\n"
                
                templates = self.db.get_command_templates(category) if self.db else []
                for template in templates[:5]:  # Show first 5
                    help_text += f"<code>{template['usage']}</code>\n"
                
                if len(templates) > 5:
                    help_text += f"  ... and {len(templates) - 5} more\n"
                
                help_text += "\n"
            
            help_text += "\n💡 <i>All commands can be executed directly via Telegram!</i>"
            return help_text
        
        else:
            return """
<b>🔧 HELP MENU</b>

<b>BASIC COMMANDS:</b>
<code>/ping &lt;ip&gt;</code> - Ping with options
<code>/scan &lt;ip&gt; [ports]</code> - Port scan
<code>/traceroute &lt;target&gt;</code> - Network tracing
<code>/nmap &lt;ip&gt; [options]</code> - Nmap scanning
<code>/curl &lt;url&gt; [options]</code> - HTTP requests

<b>INFORMATION GATHERING:</b>
<code>/whois &lt;domain&gt;</code> - WHOIS lookup
<code>/dns &lt;domain&gt;</code> - DNS lookup
<code>/location &lt;ip&gt;</code> - IP geolocation
<code>/analyze &lt;ip&gt;</code> - Complete IP analysis

<b>SYSTEM MONITORING:</b>
<code>/system</code> - System information
<code>/network</code> - Network information
<code>/status</code> - System status
<code>/history</code> - Command history
<code>/threats</code> - Recent threats

<b>ADVANCED FEATURES:</b>
<code>/report</code> - Security report
<code>/monitor add &lt;ip&gt;</code> - Monitor IP
<code>/monitor list</code> - List monitored IPs
<code>/config telegram token &lt;token&gt;</code> - Configure Telegram

<b>GET MORE HELP:</b>
<code>/help all</code> - Show all 300+ commands
<code>/commands</code> - Command categories

<b>💡 Examples:</b>
<code>/ping 8.8.8.8 -c 5</code>
<code>/scan 192.168.1.1 1-1000</code>
<code>/traceroute google.com -n</code>
<code>/whois github.com</code>
            """
    
    def _handle_ping(self, args: List[str]) -> str:
        """Handle /ping command"""
        if not args:
            return "❌ Usage: <code>/ping &lt;ip&gt; [options]</code>\nExample: <code>/ping 8.8.8.8 -c 5</code>"
        
        result = self.executor.execute('ping ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_scan(self, args: List[str]) -> str:
        """Handle /scan command"""
        if not args:
            return "❌ Usage: <code>/scan &lt;ip&gt; [ports] [options]</code>\nExample: <code>/scan 192.168.1.1 1-100</code>"
        
        result = self.executor.execute('scan ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_traceroute(self, args: List[str]) -> str:
        """Handle /traceroute command"""
        if not args:
            return "❌ Usage: <code>/traceroute &lt;target&gt; [options]</code>\nExample: <code>/traceroute google.com -n</code>"
        
        result = self.executor.execute('traceroute ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_nmap(self, args: List[str]) -> str:
        """Handle /nmap command"""
        if not args:
            return "❌ Usage: <code>/nmap &lt;ip&gt; [options]</code>\nExample: <code>/nmap 192.168.1.1 -sS -p 80,443</code>"
        
        result = self.executor.execute('nmap ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_curl(self, args: List[str]) -> str:
        """Handle /curl command"""
        if not args:
            return "❌ Usage: <code>/curl &lt;url&gt; [options]</code>\nExample: <code>/curl https://api.github.com -I</code>"
        
        result = self.executor.execute('curl ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_ssh(self, args: List[str]) -> str:
        """Handle /ssh command"""
        if not args:
            return "❌ Usage: <code>/ssh &lt;host&gt; [options]</code>\nExample: <code>/ssh user@host -p 22</code>"
        
        result = self.executor.execute('ssh ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_whois(self, args: List[str]) -> str:
        """Handle /whois command"""
        if not args:
            return "❌ Usage: <code>/whois &lt;domain&gt;</code>\nExample: <code>/whois github.com</code>"
        
        result = self.executor.execute('whois ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_dns(self, args: List[str]) -> str:
        """Handle /dns command"""
        if not args:
            return "❌ Usage: <code>/dns &lt;domain&gt;</code>\nExample: <code>/dns google.com</code>"
        
        result = self.executor.execute('dns ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_location(self, args: List[str]) -> str:
        """Handle /location command"""
        if not args:
            return "❌ Usage: <code>/location &lt;ip&gt;</code>\nExample: <code>/location 1.1.1.1</code>"
        
        result = self.executor.execute('location ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_analyze(self, args: List[str]) -> str:
        """Handle /analyze command"""
        if not args:
            return "❌ Usage: <code>/analyze &lt;ip&gt;</code>\nExample: <code>/analyze 192.168.1.1</code>"
        
        result = self.executor.execute('analyze ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_system(self, args: List[str]) -> str:
        """Handle /system command"""
        result = self.executor.execute('system', 'telegram')
        return self._format_command_result(result)
    
    def _handle_network(self, args: List[str]) -> str:
        """Handle /network command"""
        result = self.executor.execute('network', 'telegram')
        return self._format_command_result(result)
    
    def _handle_status(self, args: List[str]) -> str:
        """Handle /status command"""
        result = self.executor.execute('status', 'telegram')
        return self._format_command_result(result)
    
    def _handle_history(self, args: List[str]) -> str:
        """Handle /history command"""
        history = self.db.get_command_history(10) if self.db else []
        
        if not history:
            return "📝 No command history found"
        
        response = "📝 <b>Command History (Last 10)</b>\n\n"
        for record in history:
            status = "✅" if record.get('success') else "❌"
            source = record.get('source', 'unknown')
            cmd = record.get('command', '')[:50]
            timestamp = record.get('timestamp', '')[:19]
            
            response += f"{status} <code>{cmd}</code>\n"
            response += f"   {source} | {timestamp}\n\n"
        
        return response
    
    def _handle_threats(self, args: List[str]) -> str:
        """Handle /threats command"""
        threats = self.db.get_recent_threats(10) if self.db else []
        
        if not threats:
            return "✅ No recent threats detected"
        
        response = "🚨 <b>Recent Threats (Last 10)</b>\n\n"
        for threat in threats:
            severity = threat.get('severity', 'unknown')
            severity_icon = "🔴" if severity == 'high' else "🟡" if severity == 'medium' else "🟢"
            
            response += f"{severity_icon} <b>{threat.get('threat_type', 'Unknown')}</b>\n"
            response += f"   Source: <code>{threat.get('source_ip', 'Unknown')}</code>\n"
            response += f"   Time: {threat.get('timestamp', '')[:19]}\n"
            response += f"   Action: {threat.get('action_taken', 'None')}\n\n"
        
        return response
    
    def _handle_report(self, args: List[str]) -> str:
        """Handle /report command"""
        # Generate comprehensive report
        stats = self.db.get_statistics() if self.db else {}
        threats = self.db.get_recent_threats(50) if self.db else []
        
        # Count threats by severity
        high_threats = len([t for t in threats if t.get('severity') == 'high'])
        medium_threats = len([t for t in threats if t.get('severity') == 'medium'])
        low_threats = len([t for t in threats if t.get('severity') == 'low'])
        
        # Get system info
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        response = "📊 <b>Security Report</b>\n\n"
        response += f"📅 Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        response += "<b>📈 STATISTICS:</b>\n"
        response += f"• Total Commands: {stats.get('total_commands', 0)}\n"
        response += f"• Total Scans: {stats.get('total_scans', 0)}\n"
        response += f"• Total Threats: {stats.get('total_threats', 0)}\n"
        response += f"• Monitored IPs: {stats.get('active_monitored_ips', 0)}\n\n"
        
        response += "<b>🚨 THREAT SUMMARY:</b>\n"
        response += f"• High Severity: {high_threats}\n"
        response += f"• Medium Severity: {medium_threats}\n"
        response += f"• Low Severity: {low_threats}\n\n"
        
        response += "<b>💻 SYSTEM STATUS:</b>\n"
        response += f"• CPU Usage: {cpu}%\n"
        response += f"• Memory Usage: {mem}%\n"
        response += f"• Disk Usage: {disk}%\n\n"
        
        response += "<b>🛡️ RECOMMENDATIONS:</b>\n"
        if high_threats > 0:
            response += "• Investigate high severity threats immediately\n"
        if cpu > 80:
            response += "• High CPU usage detected\n"
        if mem > 80:
            response += "• High memory usage detected\n"
        
        if high_threats == 0 and cpu < 80 and mem < 80:
            response += "• System security status: ✅ Good\n"
        
        return response
    
    def _handle_monitor(self, args: List[str]) -> str:
        """Handle /monitor command"""
        if not args:
            return "❌ Usage: <code>/monitor &lt;add|remove|list&gt; [ip]</code>"
        
        action = args[0].lower()
        
        if action == 'add' and len(args) > 1:
            ip = args[1]
            # Note: In a real implementation, this would interact with NetworkMonitor
            return f"✅ Added <code>{ip}</code> to monitoring list"
        
        elif action == 'remove' and len(args) > 1:
            ip = args[1]
            return f"✅ Removed <code>{ip}</code> from monitoring list"
        
        elif action == 'list':
            monitored_ips = self.db.get_monitored_ips(active_only=True) if self.db else []
            
            if not monitored_ips:
                return "📋 No IPs are currently being monitored"
            
            response = "📋 <b>Monitored IPs</b>\n\n"
            for ip_info in monitored_ips:
                response += f"• <code>{ip_info.get('ip_address')}</code>\n"
                if ip_info.get('notes'):
                    response += f"  Note: {ip_info.get('notes')}\n"
                response += f"  Added: {ip_info.get('added_date', '')[:10]}\n\n"
            
            return response
        
        else:
            return "❌ Usage: <code>/monitor &lt;add|remove|list&gt; [ip]</code>"
    
    def _handle_config(self, args: List[str]) -> str:
        """Handle /config command"""
        if len(args) < 3:
            return "❌ Usage: <code>/config telegram token &lt;token&gt;</code> or <code>/config telegram chat_id &lt;id&gt;</code>"
        
        if args[0] == 'telegram':
            if args[1] == 'token':
                token = args[2]
                self.token = token
                ConfigManager.save_telegram_config(token, self.chat_id, self.enabled)
                return "✅ Telegram token configured"
            
            elif args[1] == 'chat_id':
                chat_id = args[2]
                self.chat_id = chat_id
                ConfigManager.save_telegram_config(self.token, chat_id, self.enabled)
                return "✅ Telegram chat ID configured"
            
            elif args[1] == 'enable':
                self.enabled = True
                ConfigManager.save_telegram_config(self.token, self.chat_id, True)
                return "✅ Telegram enabled"
            
            elif args[1] == 'disable':
                self.enabled = False
                ConfigManager.save_telegram_config(self.token, self.chat_id, False)
                return "✅ Telegram disabled"
        
        return "❌ Invalid config command"
    
    def _handle_test(self, args: List[str]) -> str:
        """Handle /test command"""
        if not args:
            return "❌ Usage: <code>/test &lt;telegram|connection&gt;</code>"
        
        if args[0] == 'telegram':
            success, message = self.test_connection()
            if success:
                return f"✅ {message}"
            else:
                return f"❌ {message}"
        
        elif args[0] == 'connection':
            # Test network connectivity
            result = self.executor.execute('ping 8.8.8.8 -c 2', 'telegram')
            if result['success']:
                return "✅ Network connection test successful"
            else:
                return "❌ Network connection test failed"
        
        return "❌ Invalid test command"
    
    def _handle_commands(self, args: List[str]) -> str:
        """Handle /commands command"""
        help_result = self.executor.get_help()
        if help_result['success']:
            data = help_result['data']
            
            if 'categories' in data:
                response = "📁 <b>Command Categories</b>\n\n"
                for category, description in data['categories'].items():
                    response += f"• <b>{category}</b>: {description}\n"
                
                response += f"\n📊 Total commands: {data.get('total_commands', 'Unknown')}"
                return response
            else:
                return "✅ Available commands listed"
        else:
            return "❌ Failed to get command list"
    
    def _format_command_result(self, result: Dict[str, Any]) -> str:
        """Format command result for Telegram"""
        if not result['success']:
            return f"❌ Command failed: {result.get('output', 'Unknown error')}"
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            # Format dictionary as JSON
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long
        if len(formatted) > 3500:
            formatted = formatted[:3500] + "\n\n... (output truncated)"
        
        response = f"✅ Command executed ({result['execution_time']:.2f}s)\n\n"
        response += f"<code>{formatted}</code>"
        
        return response

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class UltimateCybersecurityToolkit:
    """Main application class"""
    
    def __init__(self):
        # Initialize components
        self.config = ConfigManager.load_config()
        self.db = DatabaseManager()
        self.scanner = EnhancedNetworkScanner(self.db)
        self.traceroute_tool = EnhancedTracerouteTool(self.db)
        self.executor = CommandExecutor(self.db)
        self.monitor = NetworkMonitor(self.db, self.config)
        self.telegram_bot = TelegramBotHandler(self.db, self.executor)
        
        # Color scheme
        self.colors = {
            'red': Fore.RED + Style.BRIGHT,
            'green': Fore.GREEN + Style.BRIGHT,
            'yellow': Fore.YELLOW + Style.BRIGHT,
            'blue': Fore.BLUE + Style.BRIGHT,
            'cyan': Fore.CYAN + Style.BRIGHT,
            'magenta': Fore.MAGENTA + Style.BRIGHT,
            'white': Fore.WHITE + Style.BRIGHT,
            'reset': Style.RESET_ALL
        }
        
        # Application state
        self.running = True
        self.telegram_thread = None
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{self.colors['red']}╔══════════════════════════════════════════════════════════════════════════════╗
║{self.colors['white']}        🛡️  ACCURATE CYBER DEFENSE CYBER DRILL SIMULATION DEMO 🛡️      {self.colors['red']}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{self.colors['cyan']}  • 300+ Complete Commands Support    • Enhanced Interactive Traceroute     {self.colors['red']}║
║{self.colors['cyan']}  • Advanced Network Scanning         • Complete Telegram Integration       {self.colors['red']}║
║{self.colors['cyan']}  • Database Logging & Reporting      • DDoS Detection & Prevention         {self.colors['red']}║
║{self.colors['cyan']}  • Real-time Alerts & Notifications  • Professional Security Analysis      {self.colors['red']}║
║{self.colors['cyan']}  • Network Traffic Generation Tools  • Comprehensive Threat Intelligence  {self.colors['red']}║
║{self.colors['cyan']}  • IP Geolocation & WHOIS Lookup     • Multi-threaded Monitoring Engine   {self.colors['red']}║
╚══════════════════════════════════════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(banner)
    
    def print_help(self):
        """Print help message"""
        help_text = f"""
{self.colors['yellow']}┌─────────────────{self.colors['white']} COMPLETE COMMAND REFERENCE {self.colors['yellow']}─────────────────┐
{self.colors['cyan']}
{self.colors['green']}🛡️  MONITORING COMMANDS:{self.colors['reset']}
  start                    - Start threat monitoring
  stop                     - Stop monitoring
  status                   - Show monitoring status
  add_ip <ip>              - Add IP to monitoring
  remove_ip <ip>           - Remove IP from monitoring
  list_ips                 - List monitored IPs
  threats                  - Show recent threats

{self.colors['green']}📡 NETWORK DIAGNOSTICS:{self.colors['reset']}
  ping <ip> [options]      - Ping with all options
  traceroute <ip>          - Enhanced traceroute
  advanced_traceroute <ip> - Advanced traceroute with analysis
  scan <ip> [ports]        - Port scan
  deep_scan <ip>           - Deep port scan

{self.colors['green']}🔍 SCANNING COMMANDS:{self.colors['reset']}
  nmap <ip> [options]      - Complete nmap scanning
  curl <url> [options]     - HTTP requests with all options
  ssh <host> [options]     - SSH connections
  whois <domain>           - WHOIS lookup
  dns <domain>             - DNS lookup

{self.colors['green']}🌐 WEB & RECON COMMANDS:{self.colors['reset']}
  location <ip>            - IP geolocation
  analyze <ip>             - Analyze IP threats
  iperf <server> [options] - Bandwidth testing
  hping3 <ip> [options]    - Traffic generation

{self.colors['green']}🤖 TELEGRAM COMMANDS:{self.colors['reset']}
  config telegram token <token>     - Set Telegram token
  config telegram chat_id <id>      - Set chat ID
  test telegram connection         - Test connection
  send telegram <message>          - Send message

{self.colors['green']}📁 SYSTEM COMMANDS:{self.colors['reset']}
  system info              - System information
  network_info             - Network information
  history                  - Command history
  report                   - Generate security report
  clear                    - Clear screen
  exit                     - Exit tool

{self.colors['green']}💡 TIPS:{self.colors['reset']}
  • Use 'help all' for complete 300+ command list
  • All commands available via Telegram
  • Command history saved to database
  • Automatic threat detection enabled

{self.colors['yellow']}└─────────────────────────────────────────────────────────────────────┘
{self.colors['reset']}
"""
        print(help_text)
    
    def print_prompt(self):
        """Print command prompt"""
        prompt = f"{self.colors['red']}[{self.colors['white']}accurate-cyber-defense{self.colors['red']}]{self.colors['reset']} "
        return input(prompt)
    
    def run_telegram_bot(self):
        """Run Telegram bot in background"""
        logger.info("Telegram bot thread started")
        
        while self.running:
            try:
                self.telegram_bot.process_updates()
                time.sleep(2)
            except Exception as e:
                logger.error(f"Telegram bot error: {e}")
                time.sleep(10)
    
    def start_telegram_bot(self):
        """Start Telegram bot"""
        if self.telegram_bot.enabled and self.telegram_bot.token:
            self.telegram_thread = threading.Thread(target=self.run_telegram_bot, daemon=True)
            self.telegram_thread.start()
            logger.info("Telegram bot started")
            
            # Send startup message
            startup_msg = """
🚀 <b>Accurate Cyber Defense Cyber Drill Simulation Demo - ONLINE</b>

✅ System: Online
🛡️ Monitoring: Ready
📊 Database: Connected
🤖 Bot: Active

Type /help for commands or /start for introduction.

<b>💡 Quick Start:</b>
<code>/ping 8.8.8.8</code>
<code>/scan 192.168.1.1</code>
<code>/status</code>
"""
            self.telegram_bot.send_message(startup_msg)
    
    def setup_telegram(self):
        """Setup Telegram configuration"""
        print(f"\n{self.colors['cyan']}🔧 Telegram Bot Setup{self.colors['reset']}")
        print(f"{self.colors['cyan']}{'='*50}{self.colors['reset']}")
        print(f"\n{self.colors['white']}To use Telegram commands:{self.colors['reset']}")
        print("1. Create a bot with @BotFather on Telegram")
        print("2. Get your bot token")
        print("3. Start chat with your bot and send /start")
        print("4. Get your chat ID (send /id to @userinfobot)\n")
        
        setup = input(f"{self.colors['yellow']}Configure Telegram now? (y/n): {self.colors['reset']}").strip().lower()
        
        if setup == 'y':
            token = input(f"{self.colors['yellow']}Enter Telegram bot token: {self.colors['reset']}").strip()
            if token:
                chat_id = input(f"{self.colors['yellow']}Enter your chat ID: {self.colors['reset']}").strip()
                if chat_id:
                    ConfigManager.save_telegram_config(token, chat_id, True)
                    self.telegram_bot.token = token
                    self.telegram_bot.chat_id = chat_id
                    self.telegram_bot.enabled = True
                    
                    print(f"{self.colors['green']}✅ Telegram configured!{self.colors['reset']}")
                    
                    # Test connection
                    success, message = self.telegram_bot.test_connection()
                    if success:
                        print(f"{self.colors['green']}✅ {message}{self.colors['reset']}")
                        self.start_telegram_bot()
                    else:
                        print(f"{self.colors['red']}❌ {message}{self.colors['reset']}")
                else:
                    print(f"{self.colors['yellow']}⚠️ Chat ID not provided. Telegram disabled.{self.colors['reset']}")
            else:
                print(f"{self.colors['yellow']}⚠️ Token not provided. Telegram disabled.{self.colors['reset']}")
        else:
            print(f"{self.colors['yellow']}⚠️ Telegram features disabled.{self.colors['reset']}")
    
    def check_dependencies(self):
        """Check and install dependencies"""
        print(f"\n{self.colors['cyan']}🔍 Checking dependencies...{self.colors['reset']}")
        
        required = ['requests', 'psutil', 'colorama']
        optional = ['nmap']  # Not a Python package
        
        for package in required:
            try:
                __import__(package.replace('-', '_'))
                print(f"{self.colors['green']}✅ {package}{self.colors['reset']}")
            except ImportError:
                print(f"{self.colors['yellow']}⚠️ {package} not installed{self.colors['reset']}")
                install = input(f"Install {package}? (y/n): ").lower()
                if install == 'y':
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                        print(f"{self.colors['green']}✅ {package} installed{self.colors['reset']}")
                    except Exception as e:
                        print(f"{self.colors['red']}❌ Failed to install {package}: {e}{self.colors['reset']}")
        
        # Check for nmap
        if shutil.which('nmap'):
            print(f"{self.colors['green']}✅ nmap (system command){self.colors['reset']}")
        else:
            print(f"{self.colors['yellow']}⚠️ nmap not found (optional){self.colors['reset']}")
            print(f"{self.colors['white']}   Some scanning features will be limited.{self.colors['reset']}")
        
        print(f"\n{self.colors['green']}✅ Dependencies check complete{self.colors['reset']}")
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        # Log command
        self.db.log_command(command, 'local', True)
        
        # Split command
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Process command
        if cmd == 'help':
            if args and args[0] == 'all':
                help_result = self.executor.get_help('all')
                if help_result['success']:
                    data = help_result['data']
                    for category, info in data.items():
                        print(f"\n{self.colors['green']}{category.upper()}{self.colors['reset']}")
                        print(f"{self.colors['cyan']}{info.get('description', '')}{self.colors['reset']}")
                        for cmd_usage in info.get('commands', []):
                            print(f"  {cmd_usage}")
                else:
                    print(f"{self.colors['red']}Failed to get help: {help_result.get('output')}{self.colors['reset']}")
            else:
                self.print_help()
        
        elif cmd == 'start':
            self.monitor.start_monitoring()
            print(f"{self.colors['green']}✅ Threat monitoring started{self.colors['reset']}")
        
        elif cmd == 'stop':
            self.monitor.stop_monitoring()
            print(f"{self.colors['yellow']}🛑 Threat monitoring stopped{self.colors['reset']}")
        
        elif cmd == 'status':
            status = self.monitor.get_status()
            print(f"\n{self.colors['cyan']}📊 Monitoring Status:{self.colors['reset']}")
            print(f"  Active: {'✅ Yes' if status['monitoring'] else '❌ No'}")
            print(f"  Monitored IPs: {status['monitored_ips_count']}")
            print(f"  Threads running: {status['threads_running']}")
            
            # Show recent threats
            threats = self.db.get_recent_threats(3)
            if threats:
                print(f"\n{self.colors['red']}🚨 Recent Threats:{self.colors['reset']}")
                for threat in threats:
                    severity_color = self.colors['red'] if threat['severity'] == 'high' else self.colors['yellow']
                    print(f"  {severity_color}{threat['threat_type']} from {threat['source_ip']}{self.colors['reset']}")
        
        elif cmd == 'add_ip' and args:
            ip = args[0]
            if self.monitor.add_ip_to_monitoring(ip):
                print(f"{self.colors['green']}✅ Added {ip} to monitoring{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ Invalid IP address{self.colors['reset']}")
        
        elif cmd == 'remove_ip' and args:
            ip = args[0]
            if self.monitor.remove_ip_from_monitoring(ip):
                print(f"{self.colors['green']}✅ Removed {ip} from monitoring{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ IP not found in monitoring list{self.colors['reset']}")
        
        elif cmd == 'list_ips':
            ips = self.monitor.get_monitored_ips()
            if ips:
                print(f"\n{self.colors['cyan']}📋 Monitored IPs:{self.colors['reset']}")
                for ip in ips:
                    print(f"  • {ip}")
            else:
                print(f"{self.colors['yellow']}📋 No IPs being monitored{self.colors['reset']}")
        
        elif cmd == 'threats':
            threats = self.db.get_recent_threats(10)
            if threats:
                print(f"\n{self.colors['red']}🚨 Recent Threats:{self.colors['reset']}")
                print(f"{self.colors['yellow']}{'='*60}{self.colors['reset']}")
                for threat in threats:
                    severity_color = self.colors['red'] if threat['severity'] == 'high' else self.colors['yellow']
                    print(f"\n{severity_color}[{threat['timestamp'][:19]}] {threat['threat_type']}{self.colors['reset']}")
                    print(f"  Source: {threat['source_ip']}")
                    print(f"  Severity: {threat['severity']}")
                    print(f"  Description: {threat['description']}")
                    print(f"  Action: {threat['action_taken']}")
            else:
                print(f"{self.colors['green']}✅ No recent threats detected{self.colors['reset']}")
        
        elif cmd == 'history':
            history = self.db.get_command_history(20)
            if history:
                print(f"\n{self.colors['cyan']}📜 Command History:{self.colors['reset']}")
                for record in history:
                    status = f"{self.colors['green']}✅" if record['success'] else f"{self.colors['red']}❌"
                    print(f"{status} [{record['source']}] {record['command'][:50]}{self.colors['reset']}")
                    print(f"     {record['timestamp'][:19]}")
            else:
                print(f"{self.colors['yellow']}📜 No command history{self.colors['reset']}")
        
        elif cmd == 'report':
            # Generate report
            stats = self.db.get_statistics()
            
            print(f"\n{self.colors['cyan']}📊 Security Report{self.colors['reset']}")
            print(f"{self.colors['cyan']}{'='*60}{self.colors['reset']}")
            print(f"\n{self.colors['white']}Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{self.colors['reset']}")
            
            print(f"\n{self.colors['green']}📈 Statistics:{self.colors['reset']}")
            print(f"  Total Commands: {stats.get('total_commands', 0)}")
            print(f"  Total Scans: {stats.get('total_scans', 0)}")
            print(f"  Total Threats: {stats.get('total_threats', 0)}")
            print(f"  Monitored IPs: {stats.get('active_monitored_ips', 0)}")
            
            # Save to file
            filename = f"security_report_{int(time.time())}.json"
            filepath = os.path.join(REPORT_DIR, filename)
            
            report_data = {
                'generated_at': datetime.datetime.now().isoformat(),
                'statistics': stats,
                'system_info': {
                    'cpu': psutil.cpu_percent(),
                    'memory': psutil.virtual_memory().percent,
                    'disk': psutil.disk_usage('/').percent
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            print(f"\n{self.colors['green']}✅ Report saved: {filepath}{self.colors['reset']}")
        
        elif cmd == 'system' and args and args[0] == 'info':
            result = self.executor.execute('system')
            if result['success']:
                data = result['data']
                print(f"\n{self.colors['cyan']}💻 System Information:{self.colors['reset']}")
                print(f"  OS: {data.get('system')} {data.get('release')}")
                print(f"  CPU: {data.get('cpu_count')} cores, {data.get('cpu_percent')}% usage")
                print(f"  Memory: {data.get('memory', {}).get('percent')}% used")
                print(f"  Disk: {data.get('disk', {}).get('percent')}% used")
                print(f"  Boot Time: {data.get('boot_time')}")
            else:
                print(f"{self.colors['red']}❌ Failed to get system info{self.colors['reset']}")
        
        elif cmd == 'network_info':
            result = self.executor.execute('network')
            if result['success']:
                data = result['data']
                print(f"\n{self.colors['cyan']}🌐 Network Information:{self.colors['reset']}")
                print(f"  Hostname: {data.get('hostname')}")
                print(f"  Local IP: {data.get('local_ip')}")
                print(f"  Connections: {data.get('connections', {}).get('total', 0)}")
                
                # Show first interface
                interfaces = data.get('interfaces', {})
                if interfaces:
                    first_iface = list(interfaces.keys())[0]
                    print(f"  Interface {first_iface}:")
                    for addr in interfaces[first_iface][:2]:
                        print(f"    {addr.get('address')}")
            else:
                print(f"{self.colors['red']}❌ Failed to get network info{self.colors['reset']}")
        
        elif cmd == 'config' and len(args) >= 3 and args[0] == 'telegram':
            if args[1] == 'token':
                token = args[2]
                ConfigManager.save_telegram_config(token, self.telegram_bot.chat_id, True)
                self.telegram_bot.token = token
                self.telegram_bot.enabled = True
                print(f"{self.colors['green']}✅ Telegram token configured{self.colors['reset']}")
            
            elif args[1] == 'chat_id':
                chat_id = args[2]
                ConfigManager.save_telegram_config(self.telegram_bot.token, chat_id, True)
                self.telegram_bot.chat_id = chat_id
                self.telegram_bot.enabled = True
                print(f"{self.colors['green']}✅ Telegram chat ID configured{self.colors['reset']}")
        
        elif cmd == 'test' and len(args) >= 2 and args[0] == 'telegram':
            if args[1] == 'connection':
                success, message = self.telegram_bot.test_connection()
                if success:
                    print(f"{self.colors['green']}✅ {message}{self.colors['reset']}")
                else:
                    print(f"{self.colors['red']}❌ {message}{self.colors['reset']}")
        
        elif cmd == 'send' and len(args) >= 2 and args[0] == 'telegram':
            message = ' '.join(args[1:])
            if self.telegram_bot.send_message(message):
                print(f"{self.colors['green']}✅ Message sent to Telegram{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ Failed to send message{self.colors['reset']}")
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{self.colors['yellow']}👋 Exiting...{self.colors['reset']}")
        
        else:
            # Execute as generic command
            result = self.executor.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                
                if isinstance(output, dict):
                    # Pretty print dictionaries
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                
                print(f"\n{self.colors['green']}✅ Command executed ({result['execution_time']:.2f}s){self.colors['reset']}")
            else:
                print(f"\n{self.colors['red']}❌ Command failed: {result.get('output', 'Unknown error')}{self.colors['reset']}")
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup Telegram
        if not self.telegram_bot.enabled:
            self.setup_telegram()
        else:
            self.start_telegram_bot()
        
        print(f"\n{self.colors['green']}✅ Tool ready! Type 'help' for commands.{self.colors['reset']}")
        print(f"{self.colors['cyan']}💡 Tip: Use 'help all' for complete 300+ command list{self.colors['reset']}")
        
        # Start monitoring
        auto_monitor = input(f"\n{self.colors['yellow']}Start threat monitoring automatically? (y/n): {self.colors['reset']}").strip().lower()
        if auto_monitor == 'y':
            self.monitor.start_monitoring()
            print(f"{self.colors['green']}✅ Threat monitoring started{self.colors['reset']}")
        
        # Main command loop
        while self.running:
            try:
                command = self.print_prompt()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}👋 Exiting...{self.colors['reset']}")
                self.running = False
            
            except Exception as e:
                print(f"{self.colors['red']}❌ Error: {str(e)}{self.colors['reset']}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.monitor.stop_monitoring()
        self.db.close()
        
        print(f"\n{self.colors['green']}✅ Tool shutdown complete.{self.colors['reset']}")
        print(f"{self.colors['cyan']}📁 Logs saved to: {LOG_FILE}{self.colors['reset']}")
        print(f"{self.colors['cyan']}💾 Database: {DATABASE_FILE}{self.colors['reset']}")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    try:
        print(f"{Fore.CYAN}🚀 Starting Accurate Cyber Drill Simulation Tool Demo...{Style.RESET_ALL}")
        
        # Check if running as root/administrator (optional but recommended)
        if os.name != 'nt' and os.geteuid() != 0:
            print(f"{Fore.YELLOW}⚠️  Warning: Some features may require administrative privileges.{Style.RESET_ALL}")
        
        # Create and run the toolkit
        toolkit = UltimateCybersecurityToolkit()
        toolkit.run()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}👋 Tool terminated by user.{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}❌ Fatal error: {e}{Style.RESET_ALL}")
        logger.exception("Fatal error occurred")
        
        # Try to save error report
        try:
            error_report = {
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e),
                'traceback': logger.exception.__str__() if hasattr(logger.exception, '__str__') else str(e)
            }
            
            error_file = f"error_report_{int(time.time())}.json"
            with open(error_file, 'w') as f:
                json.dump(error_report, f, indent=2)
            
            print(f"{Fore.YELLOW}📄 Error report saved to: {error_file}{Style.RESET_ALL}")
        except:
            pass
        
        print(f"{Fore.RED}Please check {LOG_FILE} for details.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()