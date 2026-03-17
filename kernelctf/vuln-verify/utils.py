import csv
import io
import os
import re
import requests
import subprocess
import sys
import time
import textwrap

CACHE_DIR = "./"
CACHE_TIME = 0 if "--disable-cache" in sys.argv else 3600*24
CACHE_FOREVER = float("inf")

def run(cmd, cwd=None):
    shell = not isinstance(cmd, list)
    try:
        result = subprocess.check_output(cmd, cwd=cwd, shell=shell).decode('utf-8').split('\n')
        return result if result[-1] != "" else result[0:-1]
    except subprocess.CalledProcessError as e:
        print(f"[!] executing '{cmd}' failed with exit code {e.returncode}")
        return None

def readTextFile(fn):
    with open(fn, 'rt') as f: return f.read()

def writeTextFile(fn, content, append=False):
    dir = os.path.dirname(fn)
    if dir:
        os.makedirs(dir, exist_ok=True)
    mode = ('a' if append else 'w') + ('b' if type(content) is bytes else 't')
    with open(fn, mode) as f: f.write(content)

def is_cached(cache_fn, cache_time):
    return os.path.isfile(cache_fn) and (time.time() - os.path.getmtime(cache_fn) < cache_time)

def cache(getter, cache_name=None, cache_time=None):
    global CACHE_TIME
    cache_time = cache_time or CACHE_TIME
    use_cache = cache_name and cache_time
    cache_fn = f"{CACHE_DIR}/{cache_name}" if cache_name else None
    if use_cache and is_cached(cache_fn, cache_time):
        return readTextFile(cache_fn)
    result = getter()
    if use_cache:
        writeTextFile(cache_fn, result)
    return result

def fetch(url, cache_name=None, headers=None, cache_time=None, fail_on_error=True):
    def getter():
        response = requests.get(url, headers=headers)
        if fail_on_error:
            response.raise_for_status()
        return response.content.decode('utf-8')
    return cache(getter, cache_name, cache_time or CACHE_FOREVER)

def toDict(items, keyColumn):
    return { x[keyColumn]: x for x in items }

def parseCsv(csvContent, keyColumn=None):
    columns, *rows = list(csv.reader(io.StringIO(csvContent), strict=True))
    result = [{ columns[i]: row[i] for i in range(len(columns)) } for row in rows]
    return toDict(result, keyColumn) if keyColumn else result

def indent_format(text):
    text = '\n'.join(textwrap.fill(line, 120) for line in text.split('\n'))
    pad = 0
    for pad in range(len(text)):
        if text[pad] != ' ':
            break
    if pad + 1 < len(text) and text[pad] == '-' and text[pad+1] == ' ':
        pad += 2
    rows = text.split('\n')
    rows = [("" if i == 0 or not rows[i] else ' ' * (pad  - 3 if rows[i].startswith(" - ") else pad)) + rows[i] for i in range(len(rows))]
    text = '\n'.join(rows)
    return text

def printi(value):
    text = indent_format(str(value))
    print(text)
    return "\n" in text

def natural_key(text):
    # Splits the string into chunks of numbers and non-numbers
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r'(\d+)', text)]

def natsorted(items):
    return sorted(items, key=natural_key)

NO_COLOR = "--no-color" in sys.argv

def color(text, color_code):
    return text if NO_COLOR else f"\033[{color_code}m{text}\033[0m"

def red(text):
    return color(text, 31)

def green(text):
    return color(text, 32)

def yellow(text):
    return color(text, 33)

def blue(text):
    return color(text, 34)

def pink(text):
    return color(text, 35)

def cyan(text):
    return color(text, 36)

def white(text):
    return color(text, 37)

def grey(text):
    return color(text, 90)

def bold(text):
    return color(text, 1)