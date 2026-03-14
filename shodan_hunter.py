"""
ns_hunter/shodan_hunter.py — Shodan Query Runner & Normalizer
"""
import logging
import json
from datetime import datetime
from typing import Generator, Dict, Any

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

logger = logging.getLogger(__name__)


class ShodanHunter:
    def __init__(self, api_key: str, suspicious_asns: dict):
        if not SHODAN_AVAILABLE:
            raise ImportError("shodan package not installed. Run: pip install shodan")
        self.api = shodan.Shodan(api_key)
        self.suspicious_asns = suspicious_asns

    def search(self, name: str, query: str, max_results: int = 500) -> tuple[list, int]:
        """
        Führt eine Shodan-Query aus.
        Returns: (list of normalized host dicts, total_count)
        """
        logger.info(f"[Shodan] Running '{name}': {query}")
        results = []

        try:
            resp = self.api.search(query, limit=max_results)
            total = resp.get("total", 0)
            logger.info(f"[Shodan] '{name}' → {total} total, {len(resp['matches'])} fetched")

            for match in resp["matches"]:
                try:
                    normalized = self._normalize(match, query, name)
                    results.append(normalized)
                except Exception as e:
                    logger.debug(f"[Shodan] Normalize error for {match.get('ip_str')}: {e}")

        except shodan.APIError as e:
            logger.error(f"[Shodan] API error on '{name}': {e}")
            return [], 0

        return results, total

    def get_host_details(self, ip: str) -> dict:
        """Vollständige Host-Details für Pivot-Analyse."""
        try:
            return self.api.host(ip)
        except Exception as e:
            logger.debug(f"[Shodan] Host detail error {ip}: {e}")
            return {}

    def pivot_ssl_fingerprint(self, fingerprint: str, limit: int = 200) -> list:
        """
        Sucht alle Hosts mit identischem SSL-Zertifikat → ASN-Migrations-Detection.
        """
        query = f'ssl.cert.fingerprint:"{fingerprint}"'
        logger.info(f"[Pivot] SSL fingerprint: {fingerprint[:20]}...")
        results, _ = self.search("ssl_pivot", query, max_results=limit)
        for r in results:
            r["pivot_type"] = "ssl_fingerprint"
        return results

    def _normalize(self, match: dict, source_query: str, source_name: str) -> dict:
        """Normalisiert einen Shodan-Match in ein einheitliches Host-Dict."""
        ip = match.get("ip_str", "")

        # SSL
        ssl_data = match.get("ssl", {})
        cert = ssl_data.get("cert", {})
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        ssl_fp = cert.get("fingerprint", {}).get("sha256", "")
        ssl_cn = subject.get("CN", "")
        ssl_issuer_cn = issuer.get("CN", "")
        ssl_is_selfsig = int(subject == issuer and bool(subject))
        ssl_expires = cert.get("expires", "")

        # HTTP
        http_server = ""
        http_data = match.get("http", {})
        if http_data:
            http_server = http_data.get("server", "") or ""
            # Manchmal im components dict
            if not http_server:
                http_server = http_data.get("components", {}).get("server", "")

        # Ports
        open_ports = []
        for data_item in match.get("data", []) if isinstance(match.get("data"), list) else []:
            p = data_item.get("port")
            if p:
                open_ports.append(p)
        if not open_ports and match.get("port"):
            open_ports = [match["port"]]

        # ASN
        asn_raw = match.get("asn", "")
        asn_num = 0
        if asn_raw:
            try:
                asn_num = int(str(asn_raw).replace("AS", "").strip())
            except (ValueError, AttributeError):
                pass

        # Location
        loc = match.get("location", {}) or {}

        is_suspicious = int(asn_num in self.suspicious_asns)

        return {
            "ip":            ip,
            "asn":           asn_num,
            "asn_name":      match.get("org", ""),
            "country_code":  loc.get("country_code", ""),
            "country_name":  loc.get("country_name", ""),
            "city":          loc.get("city", "") or "",
            "org":           match.get("org", ""),
            "isp":           match.get("isp", ""),
            "ssl_fp":        ssl_fp,
            "ssl_cn":        ssl_cn,
            "ssl_issuer_cn": ssl_issuer_cn,
            "ssl_is_selfsig": ssl_is_selfsig,
            "ssl_expires":   ssl_expires,
            "http_server":   http_server,
            "open_ports":    json.dumps(sorted(set(open_ports))),
            "hostnames":     json.dumps(match.get("hostnames", []) or []),
            "source_query":  source_query,
            "source_name":   source_name,
            "is_suspicious": is_suspicious,
        }
