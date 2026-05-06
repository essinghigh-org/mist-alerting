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
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, cast

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
SITEGROUPS_ENDPOINT = f"{MIST_API_BASE}/orgs/{MIST_ORG_ID}/sitegroups"
ENTITY_EVENTS_ENDPOINT = f"{MIST_API_BASE}/labs/orgs/{MIST_ORG_ID}/entity_events"

# State file
LAST_TIMESTAMP_FILE = "last_alarm_timestamp.txt"
LAST_ENTITY_EVENT_TIMESTAMP_FILE = "last_entity_event_timestamp.txt"

# Cache files
ALARM_DEFINITIONS_CACHE = "alarm_definitions.json"
SITE_MAPPING_CACHE = "site_mapping.json"
SITE_DETAILS_CACHE = "site_details.json"
SITEGROUP_MAPPING_CACHE = "sitegroup_mapping.json"

# Severity order for display
SEVERITY_ORDER = ["critical", "major", "minor", "warn", "info"]

# API configuration
API_TIMEOUT = 10
MAX_RESULTS = 1000
API_MAX_RETRIES = 3
API_RETRY_STATUSES = {429, 500, 502, 503, 504}
ENTITY_EVENT_RECORD_DELAY_SECONDS = 0.1

# ============================================================================
# State Management
# ============================================================================


def mist_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = API_TIMEOUT,
) -> requests.Response:
    """GET a Mist endpoint with bounded retry/backoff for transient failures."""
    response: Optional[requests.Response] = None
    for attempt in range(API_MAX_RETRIES + 1):
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        if response.status_code not in API_RETRY_STATUSES:
            return response

        if attempt == API_MAX_RETRIES:
            return response

        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = 2**attempt
        else:
            delay = 2**attempt

        print(
            f"Warning: Mist API returned {response.status_code}; retrying in"
            f" {delay:.1f}s..."
        )
        time.sleep(delay)

    raise RuntimeError("Mist API request retry loop exited unexpectedly")


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


def get_last_processed_entity_event_timestamp() -> int:
    """Get the last processed entity event end_time in milliseconds."""
    try:
        with open(LAST_ENTITY_EVENT_TIMESTAMP_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return int((datetime.now() - timedelta(minutes=30)).timestamp() * 1000)


def save_last_processed_entity_event_timestamp(timestamp: int) -> None:
    """Save the end_time of the most recent entity event."""
    with open(LAST_ENTITY_EVENT_TIMESTAMP_FILE, "w") as f:
        f.write(str(timestamp))


# ============================================================================
# Alarm Definitions Management
# ============================================================================


def fetch_alarm_definitions() -> Dict[str, Dict[str, str]]:
    """Fetch alarm definitions from the public API endpoint."""
    try:
        response = mist_get(ALARM_DEFS_ENDPOINT, timeout=API_TIMEOUT)

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


def load_site_details() -> Dict[str, Dict[str, Any]]:
    """Load cached site metadata used to enrich indexed alarms."""
    site_details: Dict[str, Dict[str, Any]] = {}
    try:
        with open(SITE_DETAILS_CACHE, "r") as f:
            site_details = json.load(f)
        print(f"Loaded site details for {len(site_details)} sites")
    except FileNotFoundError:
        print("No existing site details found. Will fetch sites as needed.")
    except json.JSONDecodeError:
        print("Warning: Could not parse site_details.json. Will fetch sites as needed.")
    return site_details


def load_sitegroup_mapping() -> Dict[str, str]:
    """Load cached site group ID to name mapping."""
    sitegroup_mapping: Dict[str, str] = {}
    try:
        with open(SITEGROUP_MAPPING_CACHE, "r") as f:
            sitegroup_mapping = json.load(f)
        print(f"Loaded site group mapping for {len(sitegroup_mapping)} groups")
    except FileNotFoundError:
        print("No existing site group mapping found. Will fetch site groups as needed.")
    except json.JSONDecodeError:
        print(
            "Warning: Could not parse sitegroup_mapping.json. Will fetch site groups"
            " as needed."
        )
    return sitegroup_mapping


def fetch_sitegroups_if_needed(sitegroup_mapping: Dict[str, str]) -> bool:
    """Fetch site group names if not already cached."""
    if sitegroup_mapping:
        return False

    print("Fetching site group mapping...")

    headers = {
        "Authorization": f"Token {MIST_API_KEY}",
        "Accept": "application/json",
    }

    try:
        response = mist_get(
            SITEGROUPS_ENDPOINT,
            headers=headers,
            params={"limit": MAX_RESULTS, "page": 1},
            timeout=API_TIMEOUT,
        )

        if response.status_code != 200:
            print(
                "Warning: Could not fetch site groups (status"
                f" {response.status_code})"
            )
            return False

        sitegroups_data = response.json()
        if isinstance(sitegroups_data, list):
            for sitegroup in sitegroups_data:  # type: ignore[assignment]
                sitegroup_id = sitegroup.get("id")  # type: ignore[assignment]
                sitegroup_name = sitegroup.get("name")  # type: ignore[assignment]
                if sitegroup_id and sitegroup_name:
                    sitegroup_mapping[sitegroup_id] = sitegroup_name

            with open(SITEGROUP_MAPPING_CACHE, "w") as f:
                json.dump(sitegroup_mapping, f, indent=2)

            print(f"Updated site group mapping to {len(sitegroup_mapping)} groups")
            return True

    except Exception as e:
        print(f"Warning: Could not fetch site groups: {e}")

    return False


def infer_site_region(sitegroup_names: List[str]) -> Optional[str]:
    """Infer a high-level region from site group names."""
    region_tokens = {
        "EMEA": ("EMEA",),
        "APAC": ("APAC",),
        "AMER": ("AMER", "AMERICA", "AMERICAS"),
        "US": ("US", "USA", "UNITED STATES"),
    }

    for region, tokens in region_tokens.items():
        for sitegroup_name in sitegroup_names:
            upper_name = sitegroup_name.upper()
            if any(token in upper_name for token in tokens):
                return region

    return None


def fetch_sites_if_needed(
    missing_site_ids: Set[str],
    site_mapping: Dict[str, str],
    site_details: Dict[str, Dict[str, Any]],
    sitegroup_mapping: Dict[str, str],
) -> bool:
    """Fetch sites data if we have missing site IDs."""
    if not missing_site_ids:
        return False

    fetch_sitegroups_if_needed(sitegroup_mapping)

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
        sites_response = mist_get(
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
            for raw_site in cast(List[Any], sites_data):
                if not isinstance(raw_site, dict):
                    continue
                site = cast(Dict[str, Any], raw_site)
                site_id = site.get("id")
                site_name = site.get("name", "Unknown")
                if site_id:
                    site_mapping[str(site_id)] = str(site_name)
                    raw_sitegroup_ids = site.get("sitegroup_ids", [])
                    if not isinstance(raw_sitegroup_ids, list):
                        raw_sitegroup_ids = []
                    sitegroup_values = cast(List[Any], raw_sitegroup_ids)
                    sitegroup_ids = [
                        str(sitegroup_id)
                        for sitegroup_id in sitegroup_values
                        if sitegroup_id
                    ]
                    sitegroup_names = [
                        sitegroup_mapping.get(sitegroup_id, sitegroup_id)
                        for sitegroup_id in sitegroup_ids
                    ]
                    site_details[str(site_id)] = {
                        "name": site_name,
                        "sitegroup_ids": sitegroup_ids,
                        "sitegroups": sitegroup_names,
                        "region": infer_site_region(sitegroup_names),
                        "country_code": site.get("country_code"),
                        "timezone": site.get("timezone"),
                    }

            with open(SITE_MAPPING_CACHE, "w") as f:
                json.dump(site_mapping, f, indent=2)
            with open(SITE_DETAILS_CACHE, "w") as f:
                json.dump(site_details, f, indent=2)

            print(f"Updated site mapping to {len(site_mapping)} sites")
            print(f"Updated site details to {len(site_details)} sites")
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
    site_details: Dict[str, Dict[str, Any]],
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
    if site_id and site_id in site_details:
        site_detail = site_details[site_id]
        doc["site_group_ids"] = site_detail.get("sitegroup_ids", [])
        doc["site_groups"] = site_detail.get("sitegroups", [])
        doc["site_region"] = site_detail.get("region")
        doc["site_country_code"] = site_detail.get("country_code")
        doc["site_timezone"] = site_detail.get("timezone")

    doc["submitter_hostname"] = socket.gethostname()
    doc["submitter_path"] = os.path.abspath(__file__)
    doc["submitter_script"] = os.path.basename(__file__)
    doc["mist_org_id"] = MIST_ORG_ID
    doc["@timestamp"] = datetime.fromtimestamp(alarm.get("timestamp", 0)).isoformat()

    return doc


def get_site_enrichment(
    site_id: Optional[str],
    site_mapping: Dict[str, str],
    site_details: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Build common site enrichment fields for indexed documents."""
    enrichment: Dict[str, Any] = {
        "site_name": get_site_name(site_id, site_mapping) if site_id else "Unknown"
    }

    if site_id and site_id in site_details:
        site_detail = site_details[site_id]
        enrichment.update({
            "site_group_ids": site_detail.get("sitegroup_ids", []),
            "site_groups": site_detail.get("sitegroups", []),
            "site_region": site_detail.get("region"),
            "site_country_code": site_detail.get("country_code"),
            "site_timezone": site_detail.get("timezone"),
        })

    return enrichment


def parse_entity_event_record_id(record_id: str) -> Dict[str, Any]:
    """Extract useful fields from Mist labs entity event record IDs."""
    parsed: Dict[str, Any] = {}
    if not record_id or "_" not in record_id:
        return parsed

    site_id, remainder = record_id.split("_", 1)
    parsed["site_id"] = site_id

    entity_part = remainder
    event_part = ""
    if "_" in remainder and (
        remainder.find("_") < remainder.find("&") or "&" not in remainder
    ):
        entity_part, event_part = remainder.split("_", 1)
    elif "&" in remainder:
        entity_part, event_part = remainder.split("&", 1)

    parsed["record_entity_id"] = entity_part

    event_parts = event_part.split("&") if event_part else []
    if event_parts:
        if len(event_parts) >= 4:
            parsed["entity_port"] = event_parts[0]
            parsed["record_event_name"] = event_parts[1]
            parsed["record_event_type"] = event_parts[2]
            parsed["record_start_time"] = event_parts[3]
        elif len(event_parts) >= 3:
            parsed["record_event_name"] = event_parts[0]
            parsed["record_event_type"] = event_parts[1]
            parsed["record_start_time"] = event_parts[2]

    return parsed


def prepare_entity_event_document(
    event: Dict[str, Any],
    site_mapping: Dict[str, str],
    site_details: Dict[str, Dict[str, Any]],
    record_details: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Prepare an experimental entity event document for Elasticsearch indexing."""
    record_id = event.get("record_id")
    if not record_id:
        return None

    doc = dict(event)
    parsed_record = parse_entity_event_record_id(str(record_id))
    doc.update(parsed_record)
    if record_details:
        doc.update(record_details)

    event_name = str(event.get("event_name", doc.get("event_type", "unknown")))
    event_type = str(doc.get("event_type", event_name))
    doc["type_raw"] = event_name
    doc["type"] = event_name.replace("_", " ").title()
    doc["event_type"] = event_type
    doc["group"] = "infrastructure"

    site_id = doc.get("site_id")
    doc.update(get_site_enrichment(site_id, site_mapping, site_details))

    entity_id = event.get("entity_id") or doc.get("record_entity_id")
    if entity_id:
        doc["entity_mac"] = entity_id

    doc["severity"] = "warning"
    doc["source"] = "mist_labs_entity_events"
    doc["submitter_hostname"] = socket.gethostname()
    doc["submitter_path"] = os.path.abspath(__file__)
    doc["submitter_script"] = os.path.basename(__file__)
    doc["mist_org_id"] = MIST_ORG_ID

    end_time = event.get("end_time", 0)
    if isinstance(end_time, int):
        doc["@timestamp"] = datetime.fromtimestamp(end_time / 1000).isoformat()

    return doc


def flatten_named_values(value: Any) -> Any:
    """Recursively flatten Mist's list of name/value objects into dictionaries."""
    if isinstance(value, list):
        flattened: Dict[str, Any] = {}
        raw_items = cast(List[Any], value)
        for raw_item in raw_items:
            if not isinstance(raw_item, dict):
                return raw_items
            item = cast(Dict[str, Any], raw_item)
            name = item.get("name")
            if not name or "value" not in item:
                return raw_items
            flattened[str(name)] = flatten_named_values(item.get("value"))
        return flattened

    return value


def flatten_entity_event_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the labs entity event record response into indexable fields."""
    flattened: Dict[str, Any] = {}
    raw_results = record.get("results", [])
    if not isinstance(raw_results, list):
        return flattened

    results = cast(List[Any], raw_results)
    for raw_item in results:
        if not isinstance(raw_item, dict):
            continue
        item = cast(Dict[str, Any], raw_item)
        name = item.get("name")
        if not name:
            continue

        value = item.get("value")
        if name == "details" and isinstance(value, list):
            details: Dict[str, Any] = {}
            for raw_detail in cast(List[Any], value):
                if not isinstance(raw_detail, dict):
                    continue
                detail = cast(Dict[str, Any], raw_detail)
                detail_name = detail.get("name")
                detail_value = detail.get("value")
                if detail_name:
                    details[str(detail_name)] = flatten_named_values(detail_value)
            flattened["details"] = details
        else:
            flattened[str(name)] = flatten_named_values(value)

    return flattened


def fetch_entity_event_record(site_id: str, record_id: str) -> Dict[str, Any]:
    """Fetch and flatten a single labs entity event record."""
    url = f"{MIST_API_BASE}/labs/sites/{site_id}/entity_event_record"
    headers = {
        "Authorization": f"Token {MIST_API_KEY}",
        "Accept": "application/json",
    }
    response = mist_get(
        url,
        headers=headers,
        params={"record_id": record_id},
        timeout=API_TIMEOUT,
    )

    if response.status_code != 200:
        print(
            "Warning: Could not fetch entity event record"
            f" {record_id} (status {response.status_code})"
        )
        return {}

    return flatten_entity_event_record(response.json())


def index_alarms_to_elasticsearch(
    alarms: List[Dict[str, Any]],
    alarm_definitions: Dict[str, Dict[str, str]],
    site_mapping: Dict[str, str],
    site_details: Dict[str, Dict[str, Any]],
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
            doc = prepare_alarm_document(
                alarm, alarm_definitions, site_mapping, site_details
            )
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


def index_entity_events_to_elasticsearch(
    events: List[Dict[str, Any]],
    site_mapping: Dict[str, str],
    site_details: Dict[str, Dict[str, Any]],
    last_processed_timestamp: int,
    es_client: Optional[Elasticsearch],
) -> None:
    """Index labs entity events, enriching each new event with its record details."""
    if not es_client:
        return

    new_events = [
        event
        for event in events
        if event.get("end_time", 0) > last_processed_timestamp
    ]

    if not new_events:
        print("No new entity events to index to Elasticsearch")
        return

    print(
        f"Indexing {len(new_events)} new entity event(s) to Elasticsearch"
        f" (out of {len(events)} total retrieved)..."
    )

    success_count = 0
    error_count = 0

    for event in new_events:
        try:
            record_id = event.get("record_id")
            parsed_record = parse_entity_event_record_id(str(record_id or ""))
            site_id = parsed_record.get("site_id")
            record_details: Dict[str, Any] = {}

            if record_id and site_id:
                record_details = fetch_entity_event_record(site_id, str(record_id))
                time.sleep(ENTITY_EVENT_RECORD_DELAY_SECONDS)

            doc = prepare_entity_event_document(
                event, site_mapping, site_details, record_details
            )
            if not doc:
                print(f"Warning: Entity event missing record_id, skipping: {event}")
                error_count += 1
                continue

            response = es_client.index(index=ES_INDEX, document=doc)

            if response.get("result") in ["created", "updated"]:
                success_count += 1
            else:
                print(
                    "Warning: Unexpected index result for entity event"
                    f" {record_id}: {response}"
                )
                error_count += 1
        except Exception as e:
            print(
                "Error indexing entity event"
                f" {event.get('record_id', 'unknown')}: {e}"
            )
            error_count += 1

    print(
        "Entity event indexing complete:"
        f" {success_count} successful, {error_count} errors"
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

    response = mist_get(url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"Error: API returned status code {response.status_code}")
        print(f"Response: {response.text}")
        raise SystemExit(1)

    data = response.json()

    with open("alarms_response.json", "w") as f:
        json.dump(data, f, indent=2)
    print("Raw JSON response saved to alarms_response.json\n")

    return data


def fetch_entity_events(start_timestamp: int, end_timestamp: int) -> Dict[str, Any]:
    """Fetch labs entity events from Mist API within the specified time range."""
    url = ENTITY_EVENTS_ENDPOINT
    params = {
        "start": start_timestamp,
        "end": end_timestamp,
        "limit": MAX_RESULTS,
        "page": 1,
    }
    headers = {
        "Authorization": f"Token {MIST_API_KEY}",
        "Accept": "application/json",
    }

    print(
        "Fetching entity events from"
        f" {datetime.fromtimestamp(start_timestamp).strftime('%Y-%m-%d %H:%M:%S')} to"
        f" {datetime.fromtimestamp(end_timestamp).strftime('%Y-%m-%d %H:%M:%S')}..."
    )
    print(f"URL: {url}")
    print(f"Params: {params}\n")

    response = mist_get(url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"Warning: Entity events API returned status code {response.status_code}")
        print(f"Response: {response.text}")
        return {"results": []}

    data = response.json()

    with open("entity_events_response.json", "w") as f:
        json.dump(data, f, indent=2)
    print("Raw entity events JSON response saved to entity_events_response.json\n")

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


def display_entity_events(
    events: List[Dict[str, Any]],
    site_mapping: Dict[str, str],
    last_processed_timestamp: int,
) -> None:
    """Display new labs entity events in a compact table."""
    table_data: List[List[Any]] = []

    for event in events:
        if event.get("end_time", 0) <= last_processed_timestamp:
            continue

        parsed_record = parse_entity_event_record_id(str(event.get("record_id", "")))
        site_id = parsed_record.get("site_id")
        timestamp = datetime.fromtimestamp(event.get("end_time", 0) / 1000).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        table_data.append([
            timestamp,
            event.get("event_name", "N/A"),
            event.get("entity_type", "N/A"),
            event.get("entity_id", "N/A"),
            parsed_record.get("entity_port", "N/A"),
            get_site_name(site_id, site_mapping) if site_id else "N/A",
        ])

    if not table_data:
        print("No new entity events found in the specified time range.")
        return

    table_data.sort(reverse=True)
    print(f"Found {len(table_data)} NEW entity event(s):\n")
    print(
        tabulate(
            table_data,
            headers=["Timestamp", "Event", "Entity Type", "Entity", "Port", "Site"],
            tablefmt="simple",
        )
    )


# ============================================================================
# Main Execution
# ============================================================================


def main() -> None:
    """Main execution function."""
    now = datetime.now()
    end_timestamp = int(now.timestamp())
    start_timestamp = int((now - timedelta(minutes=30)).timestamp())
    last_processed_timestamp = get_last_processed_timestamp()
    last_processed_entity_event_timestamp = (
        get_last_processed_entity_event_timestamp()
    )

    print(
        "Last processed timestamp:"
        f" {datetime.fromtimestamp(last_processed_timestamp).strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    print(
        "Last processed entity event timestamp:"
        " "
        f"{datetime.fromtimestamp(last_processed_entity_event_timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

    alarm_definitions = load_alarm_definitions()
    site_mapping = load_site_mapping()
    site_details = load_site_details()
    sitegroup_mapping = load_sitegroup_mapping()
    es_client = init_elasticsearch_client()

    data = fetch_alarms(start_timestamp, end_timestamp)
    entity_events_data = fetch_entity_events(start_timestamp, end_timestamp)

    if not data.get("results"):
        print("No alarms found in the specified time range.")
        print(f"Total results: {data.get('total', 0)}")

    alarm_results = data.get("results", [])
    entity_event_results = entity_events_data.get("results", [])

    entity_event_site_ids = {
        parse_entity_event_record_id(str(event.get("record_id", ""))).get("site_id")
        for event in entity_event_results
        if event.get("record_id")
    }

    missing_site_ids = {
        alarm.get("site_id")
        for alarm in alarm_results
        if alarm.get("site_id")
        and (
            alarm.get("site_id") not in site_mapping
            or alarm.get("site_id") not in site_details
        )
    }
    missing_site_ids.update(
        site_id
        for site_id in entity_event_site_ids
        if site_id
        and (site_id not in site_mapping or site_id not in site_details)
    )

    if missing_site_ids:
        fetch_sites_if_needed(
            missing_site_ids, site_mapping, site_details, sitegroup_mapping
        )

    unknown_alarm_types = {
        alarm.get("type")
        for alarm in alarm_results
        if alarm.get("type") and alarm.get("type") not in alarm_definitions
    }

    if unknown_alarm_types:
        alarm_definitions = refetch_alarm_definitions_if_needed(
            alarm_definitions, unknown_alarm_types
        )

    display_alarms(
        alarm_results, alarm_definitions, site_mapping, last_processed_timestamp
    )
    display_entity_events(
        entity_event_results, site_mapping, last_processed_entity_event_timestamp
    )
    index_alarms_to_elasticsearch(
        alarm_results,
        alarm_definitions,
        site_mapping,
        site_details,
        last_processed_timestamp,
        es_client,
    )
    index_entity_events_to_elasticsearch(
        entity_event_results,
        site_mapping,
        site_details,
        last_processed_entity_event_timestamp,
        es_client,
    )

    if alarm_results:
        most_recent_timestamp = max(
            alarm.get("timestamp", 0) for alarm in alarm_results
        )
        save_last_processed_timestamp(most_recent_timestamp)
        print(
            "\nUpdated last processed timestamp: "
            f"{datetime.fromtimestamp(most_recent_timestamp).strftime('%Y-%m-%d %H:%M:%S')}"
        )

    if entity_event_results:
        most_recent_entity_event_timestamp = max(
            event.get("end_time", 0) for event in entity_event_results
        )
        save_last_processed_entity_event_timestamp(most_recent_entity_event_timestamp)
        print(
            "\nUpdated last processed entity event timestamp: "
            f"{datetime.fromtimestamp(most_recent_entity_event_timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')}"
        )


if __name__ == "__main__":
    main()
