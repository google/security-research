#!/usr/bin/env -S python3 -u
import csv
import io
import json
import os
import requests

def fail(msg):
    print("\n[!] [FAIL] " + msg.replace('\n', '\n    '))
    os._exit(1)

def parseCsv(csvContent):
    columns, *rows = list(csv.reader(io.StringIO(csvContent), strict=True))
    return [{ columns[i]: row[i] for i in range(len(columns)) } for row in rows]

def fetch(url):
    response = requests.get(url)
    if response.status_code != 200:
        fail(f"expected 200 OK for request: {url}")
    return response.content.decode('utf-8')

print("Fetching public spreadsheet...\n")
publicCsv = fetch("https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pub?output=csv")
publicSheet = parseCsv(publicCsv)

slots = {}
for row in publicSheet:
    for slot in [row["LTS slot"], row["COS slot"]]:
        if slot != "" and not slot.startswith("("):
            slot = slot.split(' (')[0]
            slots[slot] = (slots[slot] + ", " if slot in slots else "") + row["ID"]
slots = dict(sorted(slots.items()))

print("Taken slots:")
for slot in slots:
    print(f" - {slot}: {slots[slot]}")

print("\nSaving to slots.json")
with open("slots.json", "wt") as f: f.write(json.dumps(slots, indent=4))