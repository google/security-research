import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vuln-verify"))
from utils import extract_crash_report

BUG_LOG = """[+] exploit output
[    2.690110] kernel BUG at mm/hugetlb.c:7164!
[    2.690126] Oops: invalid opcode: 0000 [#1] SMP KASAN NOPTI
[    2.693960] CPU: 1 UID: 1000 PID: 146 Comm: exp Not tainted 7.3.0-rc1+ #3 PREEMPTLAZY 
[    2.698120] RIP: 0010:huge_pte_alloc+0x39c/0x4c0
[    2.699000] Code: 48 89 fa 4c 89 df e8 98
[    2.699001] RSP: 0018:ffffc90000a3f8b8 EFLAGS: 00010246
[    2.699002] RAX: 0000000000000000 RBX: ffff888100000000 RCX: 0000000000000000
[    2.699003] FS:  00000000004b6380(0000) GS:ffff8881f6d00000(0000) knlGS:0000000000000000
[    2.699004] CR2: 0000000020000000 CR3: 000000010a3e0000 CR4: 00000000000006f0
[    2.715637] Call Trace:
[    2.716192]  <TASK>
[    2.716702]  move_hugetlb_page_tables+0x410/0x1340
[    2.757268]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[    2.757300]  </TASK>
[    2.757301] Modules linked in:
"""

KASAN_LOG = """[   23.164030] ==================================================================
[   23.166686] BUG: KASAN: slab-use-after-free in unix_stream_read_generic+0x271a/0x2960
[   23.170132] Read of size 8 at addr ffff88814d354788 by task exp/150
[   23.172520] 
[   23.173150] Call Trace:
[   23.173152]  <TASK>
[   23.173197]  unix_stream_read_generic+0x271a/0x2960
[   23.173282] RIP: 0033:0x4483f7
[   23.173288] RSP: 002b:00007ffd23519740 EFLAGS: 00000202 ORIG_RAX: 000000000000002d
[   23.173301]  </TASK>
[   23.173302] 
[   23.256768] Allocated by task 150:
[   23.258031]  kasan_save_stack+0x30/0x50
[   23.264117]  __alloc_skb+0xf3/0x390
[   23.276170] 
[   23.276778] Freed by task 28:
[   23.277893]  kasan_save_stack+0x30/0x50
[   23.285060]  __unix_gc+0xb47/0x11b0
[   23.293194] 
[   23.293803] The buggy address belongs to the object at ffff88814d354780
[   23.293803]  which belongs to the cache skbuff_head_cache of size 224
[   23.318192] 
[   23.318801] Memory state around the buggy address:
[   23.323048]  ffff88814d354700: fb fb fb fb fc fc fc fc fc fc fc fc fc fc fc fc
[   23.325580] >ffff88814d354780: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   23.334461] ==================================================================
[   23.337300] Kernel panic - not syncing: kasan.fault=panic set ...
"""

class TestExtractCrashReport(unittest.TestCase):
    def test_kernel_bug_without_timestamps_and_registers(self):
        self.assertEqual(extract_crash_report(BUG_LOG), [
            (None, [
                "kernel BUG at mm/hugetlb.c:7164!",
                "Oops: invalid opcode: 0000 [#1] SMP KASAN NOPTI",
                "CPU: 1 UID: 1000 PID: 146 Comm: exp Not tainted 7.3.0-rc1+ #3 PREEMPTLAZY",
                "RIP: 0010:huge_pte_alloc+0x39c/0x4c0",
            ]),
            ("Crash site", [
                " <TASK>",
                " move_hugetlb_page_tables+0x410/0x1340",
                " entry_SYSCALL_64_after_hwframe+0x76/0x7e",
            ]),
        ])

    def test_kasan_report_with_allocation_and_free_sites(self):
        self.assertEqual(extract_crash_report(KASAN_LOG), [
            (None, [
                "BUG: KASAN: slab-use-after-free in unix_stream_read_generic+0x271a/0x2960",
                "Read of size 8 at addr ffff88814d354788 by task exp/150",
            ]),
            ("Crash site", [" <TASK>", " unix_stream_read_generic+0x271a/0x2960", "RIP: 0033:0x4483f7"]),
            ("Allocation site (task 150)", [" kasan_save_stack+0x30/0x50", " __alloc_skb+0xf3/0x390"]),
            ("Free site (task 28)", [" kasan_save_stack+0x30/0x50", " __unix_gc+0xb47/0x11b0"]),
        ])

    def test_no_crash(self):
        self.assertIsNone(extract_crash_report("[    1.000000] Run /init as init process\nexploit exited\n"))

    def test_no_line_cap(self):
        log = "[ 1.0] BUG: KASAN: x\n[ 1.0] Call Trace:\n" + "".join(f"[ 1.0]  frame{i}\n" for i in range(500)) + "[ 1.0]  </TASK>\n"
        self.assertEqual(len(extract_crash_report(log)[1][1]), 500)

if __name__ == "__main__":
    unittest.main()
