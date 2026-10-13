#!/usr/bin/env python3
"""
Telemetry module for sending JSON events to a local endpoint.

This module provides a function to send event dictionaries as JSON
to a specified URL (default: http://127.0.0.1:8765/telemetry).
"""

import json
import urllib.request
import urllib.error


def send_event(event, url="http://127.0.0.1:8765/telemetry"):
    """
    Send an event dictionary as JSON to the specified URL.

    Args:
        event (dict): The event data to send.
        url (str): The endpoint URL. Defaults to "http://127.0.0.1:8765/telemetry".

    Returns:
        None

    Raises:
        urllib.error.URLError: If the request fails.
    """
    data = json.dumps(event).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(req) as response:
        # We don't need to do anything with the response for now.
        pass


if __name__ == "__main__":
    # Example usage when run directly.
    test_event = {
        "event": "test",
        "message": "This is a test event from telemetry.py"
    }
    try:
        send_event(test_event)
        print("Test event sent successfully.")
    except Exception as e:
        print(f"Failed to send event: {e}")