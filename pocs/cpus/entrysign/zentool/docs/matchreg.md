# Discovering Match Registers

There is no known way to figure out the match registers, you just have to try
them and see what changes.

There is a script called `matchscan.sh` that will try every possible register
value, and then test if a change can be detected.

# Machine Preparation

Brute forcing microcode parameters will inevitably require hundreds or
thousands of reboots. The trick to completing this in a reasonable time is
rapid fault detection and fast, reliable unattended reboots.

Software fault detection helps, but sometimes your CPU is just unable to
continue. In those cases, you need a hardware watchdog. Check in your BIOS to
see if there is one you can enable -- many machines do.

If you don't have one, buy one of
[these](https://www.aliexpress.us/item/3256805248470504.html). Don't pay more
than a few dollars - it is just a relay and a microcontroller.

There is a script in the `tools` directory to use the one I have (it has USB ID
`1a86:7523` if you want the same model I have).

## BIOS Settings

We want to optimize for fast boot, so disable as many onboard devices as
possible.

Look for `Fast Boot` options, make sure slow Featues like Option ROMs, PxE,
memory testing and so on are all disabled if possible.

If you have a hardware watchdog card, remember to enable it.

## Kernel Settings

Add at least the following parameters to `/etc/default/grub`.

- This selects core 2 as your test core, and keeps as many tasks away from it as possible.
    - You shouldn't use `core 0` for testing, some people report `core 1` is also
      a [bad idea](https://manuel.bernhardt.io/posts/2023-11-16-core-pinning/).
- Prevent any automatic microcode upadting.
- Disable SMT to prevent surprises with tasks being scheduled on sibling cores.
- Reboot quickly on any detected errors or hangs.
- Disables some slow features unnescessary for testing.
- Disable `kaslr` to make userspace microcode loading simpler.


```
dis_ucode_ldr nokaslr isolcpus=domain,managed_irq,2 irqaffinity=0-1,3-N nohz_full=2 rcu_nocbs=2 nosmt panic=1 nmi_watchdog=panic,1 vga=normal nofb nomodeset selinux=0 oops=panic mce=0 mitigations=off rd.luks=0 rd.lvm=0 rd.md=0 rd.dm=0 systemd.zram=0 pci=noaer hung_task_panic=1  panic_on_warn=1 softlockup_panic=1 unknown_nmi_panic audit=0
```

If you have `rhgb` you should remove it, I also like to remove `quiet`, but that's optional.

I also used these on the beelinks, otherwise if some power event causes
`systemd` to start stopping daemons it might terminate `watchdogd`, which stops the countdown by default.

```
sp5100_tco.nowayout=1
```

### GRUB Settings

Set `GRUB_TIMEOUT=0`, and `GRUB_TIMEOUT_STYLE=countdown`. This starts the boot process as quickly as possible.

Don't set the timeout style to `menu` (the default), because that is not
interruptible with a 0 timeout. If you really want the menu, set the timeout to
at least 1.

> Note: If there is no `GRUB_TIMEOUT_STYLE`, then you are using `menu`.

Then `grub2-mkconfig -o /boot/grub2/grub.cfg`.

### Grub Menu

In an emergency, if you need the GRUB menu but set `GRUB_TIMEOUT=0`, spam `Shift` during POST.

> Note: When I say `spam`, I mean rapidly press and release continuously.

If that doesn't work due to UEFI quirks on your system, try these:

    - Holding `Shift` instead of spamming it
    - Spamming or holding `Shift+F1` (or any non-ascii key)

### Verifying `isolcpus` is working

First, check here:

```
$ cat /sys/devices/system/cpu/isolated
2
```

Now you can run `top`, type `f`, then add `P` by pressing `Space`.

generate some load and make sure no non-kernel tasks are on 2, maybe try `stress-ng`.

## Boot Services

You don't need graphics, so the first step is:

```
systemctl set-default multi-user.target
```


Dracut does a lot of slow things, you can trim down the slower modules by
omiting them. Create the file `/etc/dracut.conf.d/blacklist.conf`, and disable
boot animations and early networking:

```
omit_dracutmodules+=" network plymouth ifcfg "
```

Then you need to regenerate everything, if you specify `--hostonly`, items not
needed on this host are excluded:

```
$ sudo dracut --hostonly --regenerate-all --force
```

### Systemd

Find any slow services you can disable using `systemd-analyze`:

```
systemd-analyze blame
```

Here are some good ones you probably dont need:

```
sudo systemctl disable lvm2-monitor
sudo systemctl disable NetworkManager-wait-online.service
sudo systemctl disable cups.path
sudo systemctl disable cups.socket
sudo systemctl disable cups.service
sudo systemctl disable gssproxy.service
sudo systemctl disable thermald.service
sudo systemctl disable bluetooth.service
sudo systemctl disable virtqemud.socket
sudo systemctl disable virtqemud-admin.socket
sudo systemctl disable virtqemud-ro.socket
sudo systemctl disable virtqemud.service
sudo systemctl disable avahi-daemon.socket
sudo systemctl disable avahi-daemon.service
sudo systemctl disable ModemManager.service
sudo systemctl disable nfs-client.target
sudo systemctl disable remote-fs.target
sudo systemctl disable abrtd.service
sudo systemctl disable bluetooth.target
sudo systemctl disable tuned.service
sudo systemctl disable smartd.service
sudo systemctl disable firewalld.service
sudo systemctl mask sys-module-fuse.device
```

Disable any modules with slow initialization by creating the file `/etc/modprobe.d/blacklist.conf`

Here is a sample:

```
blacklist bluetooth
blacklist btbcm
blacklist btintel
blacklist btmtk
blacklist btrtl
blacklist btusb
blacklist cec
blacklist drm_buddy
blacklist drm_display_helper
blacklist drm_exec
blacklist drm_suballoc_helper
blacklist drm_ttm_helper
blacklist fuse
blacklist joydev
blacklist rfkill
blacklist snd
blacklist snd
blacklist snd_acp_config
blacklist snd_acp_pci
blacklist snd_ctl_led
blacklist snd_hda_codec
blacklist snd_hda_codec_generic
blacklist snd_hda_codec_realtek
blacklist snd_hda_core
blacklist snd_hda_intel
blacklist snd_hwdep
blacklist snd_pci_acp3x
blacklist snd_pci_acp5x
blacklist snd_pci_acp6x
blacklist snd_pci_ps
blacklist snd_pcm
blacklist snd_pcm_dmaengine
blacklist snd_rn_pci_acp3x
blacklist snd_rpl_pci_acp6x
blacklist snd_seq
blacklist snd_seq_device
blacklist snd_sof
blacklist snd_sof_amd_acp63
blacklist snd_sof_amd_rembrandt
blacklist snd_sof_amd_rembrandt
blacklist snd_sof_amd_renoir
blacklist snd_sof_amd_renoir
blacklist snd_sof_amd_vangogh
blacklist snd_sof_xtensa_dsp
blacklist snd_timer
blacklist snd_ump
blacklist snd_usb_audio
blacklist snd_usbmidi_lib
blacklist soundcore
blacklist soundwire_amd
blacklist ttm
blacklist video
blacklist wmi
blacklist wmi_bmof
```

If something sneaks past this, use `modprobe.blacklist=fuse`. If something is compiled in, use `initcall_blacklist`.

You can reasonably expect `systemd-analyze blame` to report a boot in ~2 seconds, if it doesn't, remove more stuff.

## Autostart

```sudo systemctl edit getty@tty1```

Add these lines:

```
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin fuzztesting --noclear %I $TERM
TTYReset=no
```

Install this utility to query shift state on the console:

```
# gcc -o /usr/bin/shift tools/shift.c
```
Now you can something like this to .bashrc:

```
if test "$(tty)" == "/dev/tty1"; then
    echo "Hold shift on boot to skip fuzzing..."
    cd zentool
    if test -e autoexec.sh; then
        if ! /usr/bin/shift; then
            bash autoexec.sh
        fi
    fi
fi
```

If you want to start fuzzing, just do `ln -s scripts/fuzzer.sh autoexec.sh`.

> Note: You may need to experiment with when to start holding shift during boot.

## Watchdogs

You will certainly break your CPU, so you will need a watchdog to reset it.

You can:

```
# yum install watchdog
# systemctl enable watchdog
```

Then add:

```
watchdog-device = /dev/watchdog
watchdog-timeout = 10
```

Maybe set timeout to 10, or 20 to be safe, I wouldn't go lower.

There is also a simple software watchdog, try this:

```
# gcc -o /usr/bin/uwatchdog tools/watchdog.c
# yum install cronie
# systemctl enable crond
# echo @reboot /usr/bin/uwatchdog | crontab
```

Sometimes your CPU will want to enter sleep state, I solve this like this:

```
$ cat panic.shutdown
#!/bin/sh
if test "${1}" != "poweroff"; then
        echo c > /proc/sysrq-trigger
fi
```

Just put that script in `/usr/lib/systemd/system-shutdown`


## Useful Settings

# Scanning

- Create a blank microcode update from a template from your system , you might need to decrypt it:

```
$ ./zentool --output matchscan.bin decrypt data/cpu00A70F41_ver0A704104_2023-07-13_3C8FAC0D.bin
$ ./zentool resign matchscan.bin
```

- Now make it run on startup:

```
$ ln -s scripts/matchscan.sh autoexec.sh
```

- Now start scanning, reboots and crazy errors are normal:
```
$ bash autoexec.sh
```

This will take many hours to complete.
