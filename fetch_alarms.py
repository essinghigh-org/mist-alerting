#!/usr/bin/env python3
"""
Juniper Mist Alert API → Elasticsearch Pipeline

Fetches alarms from Juniper Mist API and indexes them to Elasticsearch.
Maintains state via timestamp file to avoid duplicate indexing.

Usage: python3 fetch_alarms.py

Configuration:
    Requires .env file with:
    - MIST_API_KEY, MIST_PROD_ORG_ID (required)
    - ES_URL, ES_USER, ES_PASS (optional, for Elasticsearch)
"""

import json
import os
import socket
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from tabulate import tabulate

# ============================================================================
# Configuration & Constants
# ============================================================================

load_dotenv()

# Required environment variables
MIST_API_KEY = os.getenv("MIST_API_KEY")
MIST_ORG_ID = os.getenv("MIST_PROD_ORG_ID")

if not MIST_API_KEY or not MIST_ORG_ID:
    raise ValueError("MIST_API_KEY and MIST_PROD_ORG_ID must be set in .env file")

# Optional Elasticsearch configuration
ES_URL = os.getenv("ES_URL")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASS")
ES_INDEX = "mist-alerting"

# API endpoints
MIST_API_BASE = "https://api.eu.mist.com/api/v1"
ALARMS_SEARCH_ENDPOINT = f"{MIST_API_BASE}/orgs/{MIST_ORG_ID}/alarms/search"
ALARM_DEFS_ENDPOINT = f"{MIST_API_BASE}/const/alarm_defs"
SITES_ENDPOINT = f"{MIST_API_BASE}/orgs/{MIST_ORG_ID}/sites"

# State file
LAST_TIMESTAMP_FILE = "last_alarm_timestamp.txt"

# Cache files
ALARM_DEFINITIONS_CACHE = "alarm_definitions.json"
SITE_MAPPING_CACHE = "site_mapping.json"

# Severity order for display
SEVERITY_ORDER = ["critical", "major", "minor", "warn", "info"]

# API configuration
API_TIMEOUT = 10
MAX_RESULTS = 1000

# ============================================================================
# State Management
# ============================================================================


def get_last_processed_timestamp() -> int:
    """Get the timestamp of the last processed alarm, defaulting to 30 minutes ago."""
    try:
        with open(LAST_TIMESTAMP_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return int((datetime.now() - timedelta(minutes=30)).timestamp())


def save_last_processed_timestamp(timestamp: int) -> None:
    """Save the timestamp of the most recent alarm."""
    with open(LAST_TIMESTAMP_FILE, "w") as f:
        f.write(str(timestamp))


# ============================================================================
# Alarm Definitions Management
# ============================================================================


def fetch_alarm_definitions() -> Dict[str, Dict[str, str]]:
    """Fetch alarm definitions from the public API endpoint."""
    try:
        response = requests.get(ALARM_DEFS_ENDPOINT, timeout=API_TIMEOUT)

        if response.status_code != 200:
            print(
                "Warning: Could not fetch alarm definitions (status"
                f" {response.status_code})"
            )
            return {}

        definitions: List[Dict[str, Any]] = response.json()
        alarm_defs: Dict[str, Dict[str, str]] = {}

        for definition in definitions:
            key = definition.get("key")
            if key:
                alarm_defs[key] = {
                    "display": str(
                        definition.get("display", key.replace("_", " ").title())
                    ),
                    "group": str(definition.get("group", "unknown")),
                    "severity": str(definition.get("severity", "info")),
                }

        print(f"Loaded {len(alarm_defs)} alarm definitions from public API")

        with open(ALARM_DEFINITIONS_CACHE, "w") as f:
            json.dump(alarm_defs, f, indent=2)

        return alarm_defs

    except Exception as e:
        print(f"Warning: Could not fetch alarm definitions: {e}")
        return {}


def load_alarm_definitions() -> Dict[str, Dict[str, str]]:
    """Load alarm definitions from cache or fetch if not available."""
    try:
        with open(ALARM_DEFINITIONS_CACHE, "r") as f:
            alarm_defs = json.load(f)
        print(f"Loaded {len(alarm_defs)} alarm definitions from cache")
        return alarm_defs
    except FileNotFoundError:
        print("No cached alarm definitions found, fetching from API...")
        return fetch_alarm_definitions()
    except json.JSONDecodeError:
        print("Warning: Could not parse alarm_definitions.json, refetching...")
        return fetch_alarm_definitions()


def refetch_alarm_definitions_if_needed(
    alarm_definitions: Dict[str, Dict[str, str]], unknown_types: Set[str]
) -> Dict[str, Dict[str, str]]:
    """Refetch alarm definitions if we have unknown alarm types."""
    if not unknown_types:
        return alarm_definitions

    print(
        f"Found {len(unknown_types)} unknown alarm types:"
        f" {', '.join(list(unknown_types)[:5])}"
    )
    print("Refetching alarm definitions from API...")
    return fetch_alarm_definitions()


# ============================================================================
# Alarm Type/Severity Mapping
# ============================================================================


def get_alarm_metadata(
    alarm: Dict[str, Any], alarm_definitions: Dict[str, Dict[str, str]]
) -> Dict[str, str]:
    """Extract display name, severity, and group for an alarm."""
    alarm_type = alarm.get("type", "unknown")

    if alarm_type in alarm_definitions:
        defs = alarm_definitions[alarm_type]
        return {
            "display": defs["display"],
            "severity": defs["severity"].title(),
            "group": defs["group"].title(),
        }
    else:
        return {
            "display": alarm_type.replace("_", " ").title(),
            "severity": str(alarm.get("severity", "info")).title(),
            "group": str(alarm.get("group", "unknown")).title(),
        }


def get_severity_raw(
    alarm: Dict[str, Any], alarm_definitions: Dict[str, Dict[str, str]]
) -> str:
    """Get raw severity value for Elasticsearch indexing."""
    alarm_type = alarm.get("type", "unknown")
    if alarm_type in alarm_definitions:
        return alarm_definitions[alarm_type]["severity"]
    return str(alarm.get("severity", "info"))


# ============================================================================
# Site Mapping Management
# ============================================================================


def load_site_mapping() -> Dict[str, str]:
    """Load site ID to name mapping from cache file."""
    site_mapping: Dict[str, str] = {}
    try:
        with open(SITE_MAPPING_CACHE, "r") as f:
            site_mapping = json.load(f)
        print(f"Loaded site mapping for {len(site_mapping)} sites")
    except FileNotFoundError:
        print("No existing site mapping found. Will fetch sites as needed.")
    except json.JSONDecodeError:
        print("Warning: Could not parse site_mapping.json. Will fetch sites as needed.")
    return site_mapping


def fetch_sites_if_needed(
    missing_site_ids: Set[str], site_mapping: Dict[str, str]
) -> bool:
    """Fetch sites data if we have missing site IDs."""
    if not missing_site_ids:
        return False

    print(
        f"Found {len(missing_site_ids)} unknown site IDs, fetching updated sites"
        " data..."
    )

    sites_params = {"limit": MAX_RESULTS, "page": 1}
    headers = {
        "Authorization": f"Token {MIST_API_KEY}",
        "Accept": "application/json",
    }

    try:
        sites_response = requests.get(
            SITES_ENDPOINT, headers=headers, params=sites_params, timeout=API_TIMEOUT
        )

        if sites_response.status_code != 200:
            print(
                "Warning: Could not fetch sites data (status"
                f" {sites_response.status_code})"
            )
            return False

        sites_data = sites_response.json()
        if isinstance(sites_data, list):
            for site in sites_data:  # type: ignore[assignment]
                site_id = site.get("id")  # type: ignore[assignment]
                site_name = site.get("name", "Unknown")  # type: ignore[assignment]
                if site_id:
                    site_mapping[site_id] = site_name

            with open(SITE_MAPPING_CACHE, "w") as f:
                json.dump(site_mapping, f, indent=2)

            print(f"Updated site mapping to {len(site_mapping)} sites")
            return True

    except Exception as e:
        print(f"Warning: Could not fetch sites data: {e}")

    return False


def get_site_name(site_id: Optional[str], site_mapping: Dict[str, str]) -> str:
    """Get site name from ID, or return ID as fallback."""
    if site_id:
        return site_mapping.get(site_id, site_id)
    return "N/A"


# ============================================================================
# Elasticsearch Integration
# ============================================================================


def init_elasticsearch_client() -> Optional[Elasticsearch]:
    """Initialize and return Elasticsearch client, or None if not configured."""
    if not all([ES_URL, ES_USER, ES_PASS]):
        print("Elasticsearch credentials not found. Skipping ES integration.")
        return None

    try:
        es_user = ES_USER or ""
        es_pass = ES_PASS or ""
        es_client = Elasticsearch(
            ES_URL, basic_auth=(es_user, es_pass), verify_certs=False
        )
        print(f"Elasticsearch client initialized for {ES_URL}")
        return es_client
    except Exception as e:
        print(f"Warning: Could not connect to Elasticsearch: {e}")
        return None


def prepare_alarm_document(
    alarm: Dict[str, Any],
    alarm_definitions: Dict[str, Dict[str, str]],
    site_mapping: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Prepare alarm document for Elasticsearch indexing."""
    alarm_id = alarm.get("id")
    if not alarm_id:
        return None

    doc = dict(alarm)
    alarm_type = alarm.get("type", "unknown")

    if alarm_type in alarm_definitions:
        defs = alarm_definitions[alarm_type]
        doc["type"] = defs["display"]
        doc["type_raw"] = alarm_type
        doc["severity"] = defs["severity"]
        doc["group"] = defs["group"]
    else:
        doc["type_raw"] = alarm_type
        doc["type"] = alarm_type.replace("_", " ").title()

    site_id = alarm.get("site_id")
    doc["site_name"] = (
        get_site_name(site_id, site_mapping) if site_id else site_id or "Unknown"
    )

    doc["submitter_hostname"] = socket.gethostname()
    doc["submitter_path"] = os.path.abspath(__file__)
    doc["submitter_script"] = os.path.basename(__file__)
    doc["mist_org_id"] = MIST_ORG_ID
    doc["@timestamp"] = datetime.fromtimestamp(alarm.get("timestamp", 0)).isoformat()

    return doc


def index_alarms_to_elasticsearch(
    alarms: List[Dict[str, Any]],
    alarm_definitions: Dict[str, Dict[str, str]],
    site_mapping: Dict[str, str],
    last_processed_timestamp: int,
    es_client: Optional[Elasticsearch],
) -> None:
    """Index alarms to Elasticsearch, only processing alarms newer than last_processed_timestamp."""
    if not es_client:
        return

    new_alarms = [
        alarm
        for alarm in alarms
        if alarm.get("timestamp", 0) > last_processed_timestamp
    ]

    if not new_alarms:
        print("No new alarms to index to Elasticsearch")
        return

    print(
        f"Indexing {len(new_alarms)} new alarms to Elasticsearch (out of {len(alarms)}"
        " total retrieved)..."
    )

    success_count = 0
    error_count = 0

    for alarm in new_alarms:
        try:
            doc = prepare_alarm_document(alarm, alarm_definitions, site_mapping)
            if not doc:
                print(f"Warning: Alarm missing ID, skipping: {alarm}")
                error_count += 1
                continue

            alarm_id = alarm.get("id")
            response = es_client.index(index=ES_INDEX, id=alarm_id, document=doc)

            if response.get("result") in ["created", "updated"]:
                success_count += 1
            else:
                print(
                    f"Warning: Unexpected index result for alarm {alarm_id}: {response}"
                )
                error_count += 1
        except Exception as e:
            print(f"Error indexing alarm {alarm.get('id', 'unknown')}: {e}")
            error_count += 1

    print(
        f"Elasticsearch indexing complete: {success_count} successful, {error_count}"
        " errors"
    )


# ============================================================================
# Alarm Fetching
# ============================================================================


def fetch_alarms(start_timestamp: int, end_timestamp: int) -> Dict[str, Any]:
    """Fetch alarms from Mist API within the specified time range."""
    url = ALARMS_SEARCH_ENDPOINT
    params = {"start": start_timestamp, "end": end_timestamp, "limit": MAX_RESULTS}
    headers = {
        "Authorization": f"Token {MIST_API_KEY}",
        "Accept": "application/json",
    }

    print(
        "Fetching alarms from"
        f" {datetime.fromtimestamp(start_timestamp).strftime('%Y-%m-%d %H:%M:%S')} to"
        f" {datetime.fromtimestamp(end_timestamp).strftime('%Y-%m-%d %H:%M:%S')}..."
    )
    print(f"URL: {url}")
    print(f"Params: {params}\n")

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"Error: API returned status code {response.status_code}")
        print(f"Response: {response.text}")
        raise SystemExit(1)

    data = response.json()

    with open("alarms_response.json", "w") as f:
        json.dump(data, f, indent=2)
    print("Raw JSON response saved to alarms_response.json\n")

    return data


# ============================================================================
# Display Functions
# ============================================================================


def get_hostname_from_alarm(alarm: Dict[str, Any]) -> str:
    """Extract and format hostname(s) from alarm."""
    if "hostnames" in alarm and alarm["hostnames"]:
        hostnames = alarm["hostnames"][:2]
        hostname = ", ".join(hostnames)
        if len(alarm["hostnames"]) > 2:
            hostname += f" (+{len(alarm['hostnames']) - 2})"
        return hostname
    elif "hostname" in alarm:
        hostname_value = alarm.get("hostname")
        return str(hostname_value) if hostname_value is not None else "N/A"
    return "N/A"


def format_alarm_table(
    alarms: List[Dict[str, Any]],
    alarm_definitions: Dict[str, Dict[str, str]],
    site_mapping: Dict[str, str],
    last_processed_timestamp: int,
) -> List[List[Any]]:
    """Format alarms for table display, excluding already processed alarms."""
    table_data: List[List[Any]] = []

    for alarm in alarms:
        if alarm.get("timestamp", 0) <= last_processed_timestamp:
            continue

        metadata = get_alarm_metadata(alarm, alarm_definitions)

        timestamp = datetime.fromtimestamp(alarm.get("timestamp", 0)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        hostname = get_hostname_from_alarm(alarm)
        site_id = alarm.get("site_id")
        site_name = get_site_name(site_id, site_mapping) if site_id else "N/A"

        table_data.append([
            timestamp,
            metadata["display"],
            metadata["severity"],
            hostname,
            site_name,
            metadata["group"],
            alarm.get("count", 1),
            alarm.get("id", "N/A")[:8],  # Shortened ID
        ])

    table_data.sort(reverse=True)
    return table_data


def display_alarms(
    alarms: List[Dict[str, Any]],
    alarm_definitions: Dict[str, Dict[str, str]],
    site_mapping: Dict[str, str],
    last_processed_timestamp: int,
) -> None:
    """Display new alarms in a formatted table and show severity summary."""
    table_data = format_alarm_table(
        alarms, alarm_definitions, site_mapping, last_processed_timestamp
    )

    if not table_data:
        print("No new alarms found in the specified time range.")
        return

    table_headers = [
        "Timestamp",
        "Alarm Type",
        "Severity",
        "Device(s)",
        "Site",
        "Group",
        "Count",
        "ID",
    ]
    print(f"Found {len(table_data)} NEW alarm(s):\n")
    print(tabulate(table_data, headers=table_headers, tablefmt="simple"))

    severity_counts: Dict[str, int] = {}
    for alarm in alarms:
        if alarm.get("timestamp", 0) <= last_processed_timestamp:
            continue
        sev = get_severity_raw(alarm, alarm_definitions)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\nSummary by Severity:")
    for sev, count in sorted(
        severity_counts.items(),
        key=lambda x: SEVERITY_ORDER.index(x[0]) if x[0] in SEVERITY_ORDER else 999,
    ):
        print(f"  {sev.title()}: {count}")


# ============================================================================
# Main Execution
# ============================================================================


def main() -> None:
    """Main execution function."""
    now = datetime.now()
    end_timestamp = int(now.timestamp())
    start_timestamp = int((now - timedelta(minutes=30)).timestamp())
    last_processed_timestamp = get_last_processed_timestamp()

    print(
        "Last processed timestamp:"
        f" {datetime.fromtimestamp(last_processed_timestamp).strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

    alarm_definitions = load_alarm_definitions()
    site_mapping = load_site_mapping()
    es_client = init_elasticsearch_client()

    data = fetch_alarms(start_timestamp, end_timestamp)

    if not data.get("results"):
        print("No alarms found in the specified time range.")
        print(f"Total results: {data.get('total', 0)}")
        return

    missing_site_ids = {
        alarm.get("site_id")
        for alarm in data["results"]
        if alarm.get("site_id") and alarm.get("site_id") not in site_mapping
    }

    if missing_site_ids:
        fetch_sites_if_needed(missing_site_ids, site_mapping)

    unknown_alarm_types = {
        alarm.get("type")
        for alarm in data["results"]
        if alarm.get("type") and alarm.get("type") not in alarm_definitions
    }

    if unknown_alarm_types:
        alarm_definitions = refetch_alarm_definitions_if_needed(
            alarm_definitions, unknown_alarm_types
        )

    display_alarms(
        data["results"], alarm_definitions, site_mapping, last_processed_timestamp
    )
    index_alarms_to_elasticsearch(
        data["results"],
        alarm_definitions,
        site_mapping,
        last_processed_timestamp,
        es_client,
    )

    if data["results"]:
        most_recent_timestamp = max(
            alarm.get("timestamp", 0) for alarm in data["results"]
        )
        save_last_processed_timestamp(most_recent_timestamp)
        print(
            "\nUpdated last processed timestamp: "
            f"{datetime.fromtimestamp(most_recent_timestamp).strftime('%Y-%m-%d %H:%M:%S')}"
        )


if __name__ == "__main__":
    main()
