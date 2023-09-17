#!/usr/bin/env -S python3 -u
import base64
import json
import os
import re

with open("steps.json", "rt") as f: steps = json.loads(f.read())

repros = [{ "idx": id[len("repro"):], **step } for (id,step) in steps.items() if id.startswith("repro")]
print(repros)

success_count = 0
for repro in repros:
    success = repro["outcome"] == "success"
    repro["icon"] = "✅" if success else "❌"
    success_count += 1 if success else 0

result = f"""
# Reproduction summary

Reliability: {'%d' % (success_count / len(repros) * 100)}%

Runs: {' '.join(x['icon'] for x in repros)}"""

for repro in repros:
    result += f"\n\n## Reproduction {repro['idx']} / {len(repros)} - {repro['icon']}\n\n"

    run_time = repro["outputs"].get("RUN_TIME")
    if run_time:
        result += f"Time: {run_time}s\n\n"

    repro_log_fn = f"repro_log_{repro['idx']}.txt"
    if os.path.isfile(repro_log_fn):
        with open(repro_log_fn, 'rb') as f: repro_log = f.read()

        repro_log = repro_log.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n').decode('utf-8')

        def split(pattern, last=False):
            arr = repro_log.rsplit(pattern, 1) if last else repro_log.split(pattern, 1)
            return arr[1].strip() if len(arr) == 2 else ""

        def getLastLine(pattern):
            return split(pattern, True).split('\n')[0].strip()

        panic = getLastLine('Kernel panic - ')
        if "Attempted to kill init!" in panic:
            result += f"The kernel did not panic (init exited).\n\n"
        elif panic:
            result += f"Kernel panic: `{panic}`\n\nRIP: `{getLastLine('RIP: ')}`\n\n"

        repro_error = getLastLine('Repro error: ')
        if repro_error:
            result += f"Error during reproduction: `{repro_error}`.\n\n"

        expl_out = split('::EXPLOIT OUTPUT FROM HERE::\n')

        m = re.search(r"exploit.*?: (segfault at.*)", expl_out)
        if m:
            result += f"The exploit crashed: `{m.groups()[0]}`.\n\n"

        if expl_out:
            result += f"""
<details>
    <summary>Exploit / QEMU output</summary>

```
{expl_out.replace('`', '')}
```

</details>
"""

print(result)

if "GITHUB_STEP_SUMMARY" in os.environ:
    with open(os.environ["GITHUB_STEP_SUMMARY"], 'at') as f: f.write(result.strip() + "\n")

os._exit(1 if success_count == 0 else 0)