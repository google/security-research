import csv
import io
import json
import os
import subprocess
import re
import requests
import time
from urllib.parse import urlparse

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CACHE_DIR = f"{BASE_DIR}/.cache"

errors = []
warnings = []

def error(msg):
    global errors
    msg = msg.replace('\n', '\n    ')
    errors.append(msg)
    print(f"\n[!] [ERROR] {msg}")

def warning(msg):
    global warnings
    msg = msg.replace('\n', '\n    ')
    warnings.append(msg)
    print(f"\n[!] [WARN] {msg}")

def fail(msg):
    print("\n[!] [FAIL] " + msg.replace('\n', '\n    '))
    # os._exit(1)

def run(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').split('\n')
        return result if result[-1] != "" else result[0:-1]
    except subprocess.CalledProcessError as e:
        fail(f"executing '{cmd}' failed with exit code {e.returncode}")

def subdirEntries(files, subdir):
    return list(set([f[len(subdir):].split('/')[0] for f in files if f.startswith(subdir)]))

def formatList(items, nl=False):
    return ('\n' if nl else '').join([f"\n - {item}" for item in items])

def printList(title, items):
    print(f"\n{title}:" + formatList(items))

def errorList(errorMsg, items, warningOnly=False):
    itemsStr = ", ".join(f"`{x}`" for x in items)
    errorMsg = errorMsg.replace("<LIST>", itemsStr) if "<LIST>" in errorMsg else f"{errorMsg}: {itemsStr}"
    if warningOnly:
        warning(errorMsg)
    else:
        error(errorMsg)

def checkOnlyOne(list, errorMsg):
    if len(list) > 1:
        errorList(errorMsg, list)
    return list[0]

def checkList(items, isAllowedFunc, errorMsg, warningOnly=False):
    disallowedItems = [item for item in items if not isAllowedFunc(item)]
    if len(disallowedItems) > 0:
        errorList(errorMsg, disallowedItems, warningOnly)
    return list(sorted(set(items) - set(disallowedItems)))

def checkAtLeastOne(list, errorMsg):
    if len(list) == 0:
        fail(errorMsg)

def checkRegex(text, pattern, errorMsg):
    m = re.match(pattern, text)
    if not m:
        error(f"{errorMsg}. Must match regex `{pattern}`")
    return m

def fetch(url, cache_name=None, cache_time=3600):
    if not cache_name:
        cache_name = os.path.basename(urlparse(url).path)
    cache_fn = f"{CACHE_DIR}/{cache_name}"
    if cache_name and os.path.isfile(cache_fn) and (time.time() - os.path.getmtime(cache_fn) < cache_time):
        with open(cache_fn, "rb") as f: return f.read().decode('utf-8')

    response = requests.get(url)
    if response.status_code != 200:
        fail(f"expected 200 OK for request: {url}")

    if cache_name:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(cache_fn, "wb") as f: f.write(response.content)

    return response.content.decode('utf-8')

def parseCsv(csvContent):
    columns, *rows = list(csv.reader(io.StringIO(csvContent), strict=True))
    return [{ columns[i]: row[i] for i in range(len(columns)) } for row in rows]

def ghSet(varName, content):
    varName = f"GITHUB_{varName}"
    print(f"[+] Writing {json.dumps(content)} to ${varName}")
    if varName in os.environ:
        with open(os.environ[varName], 'at') as f: f.write(content + "\n")
