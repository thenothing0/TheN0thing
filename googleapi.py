#!/usr/bin/env python3
"""
Google Maps API Key Vulnerability Tester
-----------------------------------------
Checks which Google Maps Platform services a given API key can access,
which helps reveal keys that are missing proper API/referrer/IP restrictions.
"""

import json
import logging
import sys

import requests
import urllib3
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    filename="api_key_testing.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

REQUEST_TIMEOUT = 10  # seconds, avoids the script hanging forever on a dead endpoint

RED = "\033[1;31;40m"
GREEN = "\033[1;32;40m"
RESET = "\033[0m"

# Phrases Google renders on an error page/response even when the HTTP status is 200,
# used for endpoints that don't return clean JSON (Embed API).
ERROR_MARKERS = [
    "this api project is not authorized",
    "the provided api key is invalid",
    "api key not valid",
    "referernotallowedmaperror",
    "invalidkeymaperror",
    "apinotactivatedmaperror",
    "missingkeymaperror",
    "rejected your request",
]


def _looks_like_error(text):
    lowered = text.lower()
    return any(marker in lowered for marker in ERROR_MARKERS)


def _report_vulnerable(api_name, url, extra=""):
    print(f"API key is {RED}vulnerable{RESET} for {api_name}! Here is the link:")
    print(url)
    if extra:
        print(extra)
    logging.info("VULNERABLE - %s - %s", api_name, url)


def _report_safe(api_name, reason):
    print(f"{GREEN}Not vulnerable{RESET} for {api_name}")
    print(f"Reason: {reason}")
    logging.info("safe - %s - %s", api_name, reason)


def test_api(url, api_name, response_kind="json"):
    """
    response_kind controls how a "successful" response is validated, since a
    200 OK on its own does NOT mean the key worked for many Maps APIs:

      'json'  -> legacy web-service APIs put errors in a `status` (and/or
                 `error`) field INSIDE a 200 OK body — Directions, Geocoding,
                 Distance Matrix, Places (Find Place / Autocomplete),
                 Elevation, Time Zone, and Roads all behave this way.
      'image' -> Static Map / Street View are expected to return image bytes.
      'html'  -> Embed API returns an iframe-able HTML page; on failure it
                 still returns 200 with an error message baked into the page.
    """
    try:
        response = requests.get(url, verify=False, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except RequestException as e:
        _report_safe(api_name, str(e))
        return False

    if response_kind == "json":
        try:
            data = response.json()
        except ValueError:
            _report_safe(api_name, "response was not valid JSON")
            return False

        status = data.get("status")
        if status not in (None, "OK", "ZERO_RESULTS"):
            note = (
                " (key may still be valid for this API but is rate-limited)"
                if status == "OVER_QUERY_LIMIT"
                else ""
            )
            _report_safe(
                api_name,
                f"API returned status '{status}'{note}: {data.get('error_message', '')}",
            )
            return False
        if "error" in data:
            _report_safe(api_name, str(data["error"]))
            return False

    elif response_kind == "image":
        content_type = response.headers.get("Content-Type", "")
        if not content_type.startswith("image/"):
            _report_safe(api_name, f"expected an image, got Content-Type '{content_type}'")
            return False

    elif response_kind == "html":
        if _looks_like_error(response.text):
            _report_safe(api_name, "response page contains a Google Maps error message")
            return False

    _report_vulnerable(api_name, url)
    return True


def test_post_api(url, api_name, postdata):
    try:
        response = requests.post(url, json=postdata, verify=False, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except RequestException as e:
        _report_safe(api_name, str(e))
        return False

    try:
        data = response.json()
    except ValueError:
        _report_safe(api_name, "response was not valid JSON")
        return False

    if "error" in data:
        _report_safe(api_name, str(data["error"]))
        return False

    body = json.dumps(postdata)
    curl_cmd = f"curl -i -s -k -X POST -H 'Content-Type: application/json' --data '{body}' '{url}'"
    _report_vulnerable(api_name, url, extra=curl_cmd)
    return True


def print_ascii_intro(github_username):
    intro = r'''
            Welcome to Google Maps API Key Vulnerability Tester!
        
  ████████╗██╗  ██╗███████╗███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗███╗   ██╗ ██████╗
  ╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝
     ██║   ███████║█████╗  ██╔██╗ ██║██║   ██║   ██║   ███████║██║██╔██╗ ██║██║  ███╗
     ██║   ██╔══██║██╔══╝  ██║╚██╗██║██║   ██║   ██║   ██╔══██║██║██║╚██╗██║██║   ██║
     ██║   ██║  ██║███████╗██║ ╚████║╚██████╔╝   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝
     ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝

        '''
    print(intro)
    print(f" {github_username}\n")


def build_get_endpoints(apikey):
    """(name, url, response_kind) for every endpoint tested with a GET request."""
    return [
        ("Staticmap", f"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={apikey}", "image"),
        ("Streetview", f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={apikey}", "image"),
        ("Embed (Basic-Free)", f"https://www.google.com/maps/embed/v1/place?q=Seattle&key={apikey}", "html"),
        ("Embed (Advanced-Paid)", f"https://www.google.com/maps/embed/v1/search?q=record+stores+in+Seattle&key={apikey}", "html"),
        ("Directions", f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={apikey}", "json"),
        ("Geocode", f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}", "json"),
        ("Distance Matrix", f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592&key={apikey}", "json"),
        ("Find Place From Text", f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={apikey}", "json"),
        ("Autocomplete", f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={apikey}", "json"),
        ("Elevation", f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={apikey}", "json"),
        ("Timezone", f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={apikey}", "json"),
        ("Roads", f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key={apikey}", "json"),
    ]


def main():
    logging.info("=== New test run ===")
    print_ascii_intro("as-squirrel")

    vulnerable_apis = []
    apikey = input("Enter the Google Maps API Key > ").strip()

    if not apikey:
        print("No API key entered, exiting.")
        sys.exit(1)

    for api_name, endpoint_url, kind in build_get_endpoints(apikey):
        if test_api(endpoint_url, api_name, response_kind=kind):
            vulnerable_apis.append(api_name)
        print()

    # Geolocation is POST-only; a GET request 404s regardless of the key,
    # which is why it needs its own call instead of going through test_api().
    geolocation_url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={apikey}"
    if test_post_api(geolocation_url, "Geolocation", {"considerIp": True}):
        vulnerable_apis.append("Geolocation")

    print("\nResults:")
    if vulnerable_apis:
        for api in vulnerable_apis:
            print(f"- {api}")
    else:
        print("No over-permissioned endpoints found for this key.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
