# v8CTF Rules

The v8CTF is a part of the [Google VRP](https://g.co/vrp) in which we reward successful exploitation attempts against a V8 version running on our infrastructure.
This program is orthogonal to the [Chrome VRP](https://g.co/chrome/vrp), if you find a bug and exploit it, you can submit the bug to the Chrome VRP and use the exploit for the v8CTF.

## Rules

The following rules apply to the eligibility of exploits starting with M156:
* Your exploit needs to exfiltrate the flag from our v8CTF infrastructure.
* Every bug used in the submission (e.g. V8 memory corruption, V8 sandbox) must have been found by you as the first reporter.
* Exploits need to be reasonably fast and stable. We accept submissions with an average runtime of less than 1 minute and at least 80% success rate.
* Valid submissions get a reward of $20,000.

## Submission Process

1. Make sure to report the bugs first to the [Chrome VRP](https://g.co/chrome/vrp).
1. Exploit the bug and capture the flag from our v8CTF environment.
    1. The flag format is v8CTF{$unix_timestamp:$signature}.
1. Create a .tar.gz archive of your exploit and calculate its sha256, e.g. with `sha256sum exploit.tar.gz`.
    1. Provide an archive that can be verified using our reproduction setup (see [kctf/challenge-templates/repro-chrome/README.md](kctf/challenge-templates/repro-chrome/README.md))
    1. Please double check that the exploit doesn’t have any external dependencies.
1. Fill out [this form](https://docs.google.com/forms/d/e/1FAIpQLScoWE5-XoF85dXMjWKTIrJGTEfCybFaktsYZMCZ86iFPrW8Ew/viewform?usp=header_link) with the flag and the exploit sha256 sum. You need to use the same email address you reported the bugs from.
1. A bug in the Google Issue Tracker will be filed on your behalf. Attach the exploit matching the sha256 sum and a short write up to the bug.
1. Give us a few days to validate your submission.

## Setup

You can find a description of our v8CTF infrastructure in the [README](https://github.com/google/security-research/blob/master/v8ctf/README.md).

## Communication

We have two discord channels set up on the [Capture The Flag](https://discord.gg/hqcSdTk6vm) server:

* #v8ctf-announcements: will be used for announcements such as changes to the rules and the start time for n-day submissions.
* #v8ctf: is open to all. If you have any questions, please ask here.

And you can find data about existing submissions in [this sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vTWvO0tFNl8fJbOmTV1nwGJi4fAy5pDg-6DsHARRubj8I6c7_11RQ36Jv735zj9EQggz6AWjAOaebJh/pubhtml).
