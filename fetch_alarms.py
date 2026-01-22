#!/usr/bin/env python3
import os
import json
import socket
from typing import Any, Dict, List, Optional, Set
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from tabulate import tabulate
from elasticsearch import Elasticsearch

load_dotenv()

MIST_API_KEY = os.getenv("MIST_API_KEY")
MIST_ORG_ID = os.getenv("MIST_PROD_ORG_ID")

if not MIST_API_KEY or not MIST_ORG_ID:
    raise ValueError("MIST_API_KEY and MIST_PROD_ORG_ID must be set in .env file")

LAST_TIMESTAMP_FILE = "last_alarm_timestamp.txt"


def get_last_processed_timestamp() -> int:
    """Get the timestamp of the last processed alarm"""
    try:
        with open(LAST_TIMESTAMP_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return int((datetime.now() - timedelta(minutes=30)).timestamp())


def save_last_processed_timestamp(timestamp: int) -> None:
    """Save the timestamp of the most recent alarm"""
    with open(LAST_TIMESTAMP_FILE, "w") as f:
        f.write(str(timestamp))


now = datetime.now()
thirty_minutes_ago = now - timedelta(minutes=30)
end_timestamp = int(now.timestamp())
start_timestamp = int(thirty_minutes_ago.timestamp())
last_processed_timestamp = get_last_processed_timestamp()

url = f"https://api.eu.mist.com/api/v1/orgs/{MIST_ORG_ID}/alarms/search"
params = {"start": start_timestamp, "end": end_timestamp, "limit": 1000}

headers: Dict[str, str] = {
    "Authorization": f"Token {MIST_API_KEY}",
    "Accept": "application/json",
}


def fetch_alarm_definitions() -> Dict[str, Dict[str, str]]:
    """Fetch alarm definitions from the public API endpoint"""
    try:
        defs_url = "https://api.eu.mist.com/api/v1/const/alarm_defs"
        response = requests.get(defs_url, timeout=10)

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

        with open("alarm_definitions.json", "w") as f:
            json.dump(alarm_defs, f, indent=2)

        return alarm_defs

    except Exception as e:
        print(f"Warning: Could not fetch alarm definitions: {e}")
        return {}


def load_alarm_definitions() -> Dict[str, Dict[str, str]]:
    """Load alarm definitions from cache or fetch if not available"""
    try:
        with open("alarm_definitions.json", "r") as f:
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
    """Refetch alarm definitions if we have unknown alarm types"""
    if not unknown_types:
        return alarm_definitions

    print(
        f"Found {len(unknown_types)} unknown alarm types:"
        f" {', '.join(list(unknown_types)[:5])}"
    )
    print("Refetching alarm definitions from API...")
    return fetch_alarm_definitions()


alarm_definitions = load_alarm_definitions()

ES_URL = os.getenv("ES_URL")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASS")
ES_INDEX = "mist-alerting"

es_client = None
if ES_URL and ES_USER and ES_PASS:
    try:
        es_client = Elasticsearch(
            ES_URL,
            basic_auth=(ES_USER, ES_PASS),
            verify_certs=False,
        )
        print(f"Elasticsearch client initialized for {ES_URL}")
    except Exception as e:
        print(f"Warning: Could not connect to Elasticsearch: {e}")
        es_client = None
else:
    print("Elasticsearch credentials not found. Skipping ES integration.")

print(
    f"Fetching alarms from {thirty_minutes_ago.strftime('%Y-%m-%d %H:%M:%S')} to"
    f" {now.strftime('%Y-%m-%d %H:%M:%S')}..."
)
print(
    "Last processed timestamp:"
    f" {datetime.fromtimestamp(last_processed_timestamp).strftime('%Y-%m-%d %H:%M:%S')}"
)
print(f"URL: {url}")
print(f"Params: {params}\n")

response = requests.get(url, headers=headers, params=params)

if response.status_code != 200:
    print(f"Error: API returned status code {response.status_code}")
    print(f"Response: {response.text}")
    exit(1)

with open("alarms_response.json", "w") as f:
    json.dump(response.json(), f, indent=2)
print("Raw JSON response saved to alarms_response.json\n")

site_mapping: Dict[str, str] = {}
try:
    with open("site_mapping.json", "r") as f:
        site_mapping = json.load(f)
    print(f"Loaded site mapping for {len(site_mapping)} sites")
except FileNotFoundError:
    print("No existing site mapping found. Will fetch sites as needed.")
except json.JSONDecodeError:
    print("Warning: Could not parse site_mapping.json. Will fetch sites as needed.")
    site_mapping = {}


def fetch_sites_if_needed(missing_site_ids: Set[str]) -> bool:
    """Fetch sites data if we have missing site IDs"""
    if not missing_site_ids:
        return False

    print(
        f"Found {len(missing_site_ids)} unknown site IDs, fetching updated sites"
        " data..."
    )

    sites_url = f"https://api.eu.mist.com/api/v1/orgs/{MIST_ORG_ID}/sites"
    sites_params = {"limit": 1000, "page": 1}

    sites_response = requests.get(sites_url, headers=headers, params=sites_params)

    if sites_response.status_code != 200:
        print(
            f"Warning: Could not fetch sites data (status {sites_response.status_code})"
        )
        return False

    sites_data: Any = sites_response.json()
    if isinstance(sites_data, list):
        for site in sites_data:  # type: ignore
            site_id: Optional[str] = site.get("id")  # type: ignore
            site_name: str = site.get("name", "Unknown")  # type: ignore
            if site_id:
                site_mapping[site_id] = site_name

        with open("site_mapping.json", "w") as f:
            json.dump(site_mapping, f, indent=2)

        print(f"Updated site mapping to {len(site_mapping)} sites")
        return True

    return False


def index_alarms_to_elasticsearch(
    alarms: List[Dict[str, Any]],
    site_mapping: Dict[str, str],
    last_processed_timestamp: int,
) -> None:
    """Index alarms to Elasticsearch, only processing alarms newer than last_processed_timestamp"""
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
            doc: Dict[str, Any] = dict(alarm)  # Copy all original fields
            alarm_type: str = alarm.get("type", "unknown")
            if alarm_type in alarm_definitions:
                doc["type"] = alarm_definitions[alarm_type]["display"]
                doc["type_raw"] = alarm_type  # Keep original in type_raw field
                doc["severity"] = alarm_definitions[alarm_type]["severity"]
                doc["group"] = alarm_definitions[alarm_type]["group"]
            else:
                doc["type_raw"] = alarm_type
                doc["type"] = alarm_type.replace("_", " ").title()
            site_id: Optional[str] = alarm.get("site_id")
            if site_id and site_id in site_mapping:
                doc["site_name"] = site_mapping[site_id]
            else:
                doc["site_name"] = site_id if site_id else "Unknown"
            doc["submitter_hostname"] = socket.gethostname()
            doc["submitter_path"] = os.path.abspath(__file__)
            doc["submitter_script"] = os.path.basename(__file__)
            doc["mist_org_id"] = MIST_ORG_ID
            doc["@timestamp"] = datetime.fromtimestamp(
                alarm.get("timestamp", 0)
            ).isoformat()
            alarm_id: Optional[str] = alarm.get("id")
            if alarm_id:
                response = es_client.index(index=ES_INDEX, id=alarm_id, document=doc)
                if response.get("result") in ["created", "updated"]:
                    success_count += 1
                else:
                    print(
                        f"Warning: Unexpected index result for alarm {alarm_id}:"
                        f" {response}"
                    )
                    error_count += 1
            else:
                print(f"Warning: Alarm missing ID, skipping: {alarm}")
                error_count += 1
        except Exception as e:
            print(f"Error indexing alarm {alarm.get('id', 'unknown')}: {e}")
            error_count += 1
    print(
        f"Elasticsearch indexing complete: {success_count} successful, {error_count}"
        " errors"
    )


print()
data: Dict[str, Any] = response.json()

if "results" in data and len(data["results"]) > 0:
    missing_site_ids: Set[str] = set()
    for alarm in data["results"]:
        site_id: Optional[str] = alarm.get("site_id")
        if site_id and site_id not in site_mapping:
            missing_site_ids.add(site_id)

    if missing_site_ids:
        fetch_sites_if_needed(missing_site_ids)
    unknown_alarm_types: Set[str] = set()
    for alarm in data["results"]:
        alarm_type: str = alarm.get("type", "unknown")
        if alarm_type != "unknown" and alarm_type not in alarm_definitions:
            unknown_alarm_types.add(alarm_type)
    if unknown_alarm_types:
        alarm_definitions = refetch_alarm_definitions_if_needed(
            alarm_definitions, unknown_alarm_types
        )

    table_data: List[List[Any]] = []
    for alarm in data["results"]:
        if alarm.get("timestamp", 0) <= last_processed_timestamp:
            continue

        alarm_type: str = alarm.get("type", "unknown")
        if alarm_type in alarm_definitions:
            friendly_name: str = alarm_definitions[alarm_type]["display"]
            severity: str = alarm_definitions[alarm_type]["severity"].title()
            group: str = alarm_definitions[alarm_type]["group"].title()
        else:
            friendly_name = alarm_type.replace("_", " ").title()
            severity = str(alarm.get("severity", "info")).title()
            group = str(alarm.get("group", "unknown")).title()

        timestamp: str = datetime.fromtimestamp(alarm.get("timestamp", 0)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        hostname: str = "N/A"
        if "hostnames" in alarm and alarm["hostnames"]:
            hostname = ", ".join(alarm["hostnames"][:2])  # Show first 2
            if len(alarm["hostnames"]) > 2:
                hostname += f' (+{len(alarm["hostnames"])-2})'
        elif "hostname" in alarm:
            hostname_value = alarm.get("hostname")
            hostname = str(hostname_value) if hostname_value is not None else "N/A"
        site_id: Optional[str] = alarm.get("site_id")  # type: ignore
        site_name: str
        if site_id:
            site_name = site_mapping.get(site_id, site_id)
        else:
            site_name = "N/A"

        table_data.append([
            timestamp,
            friendly_name,
            severity,
            hostname,
            site_name,
            group,
            alarm.get("count", 1),
            alarm.get("id", "N/A")[:8],  # Shortened ID
        ])
    table_data.sort(reverse=True)

    table_headers: List[str] = [
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
    for alarm in data["results"]:
        if alarm.get("timestamp", 0) <= last_processed_timestamp:
            continue

        alarm_type: str = alarm.get("type", "unknown")
        if alarm_type in alarm_definitions:
            sev: str = alarm_definitions[alarm_type]["severity"]
        else:
            sev: str = str(alarm.get("severity", "info"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\nSummary by Severity:")
    for sev, count in sorted(
        severity_counts.items(),
        key=lambda x: (
            ["critical", "major", "minor", "warn", "info"].index(x[0])
            if x[0] in ["critical", "major", "minor", "warn", "info"]
            else 999
        ),
    ):
        print(f"  {sev.title()}: {count}")

    index_alarms_to_elasticsearch(
        data["results"], site_mapping, last_processed_timestamp
    )

    if data["results"]:
        most_recent_timestamp = max(
            alarm.get("timestamp", 0) for alarm in data["results"]
        )
        save_last_processed_timestamp(most_recent_timestamp)
        print(
            "\nUpdated last processed timestamp:"
            f" {datetime.fromtimestamp(most_recent_timestamp).strftime('%Y-%m-%d %H:%M:%S')}"
        )

else:
    print("No alarms found in the specified time range.")
    print(f"Total results: {data.get('total', 0)}")
