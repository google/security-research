# Frequently Asked Questions (FAQ)

### Q: I submitted one report to [bughunters.google.com](https://bughunters.google.com/) containing multiple exploits. I noticed that some of the associated pull requests have been merged, and I received a payment notification email from kernelCTF awarding only partial rewards (not for all submitted exploits). When will I receive all the bounties?

A: The above described situation means that at this moment only some of the exploits have been reviewed, the rest of exploits associated with the report remain in the review queue. We are doing everything possible to prioritize review of similar submissions and bundle them together, but sometimes we still need more time to make a decision on all the exploits provided. Please stay tuned for the updates on the remaining pull requests. As soon as other pull requests are merged the subsequent bounties will also be issued. 

### Q: How can I rebuild a kernelCTF target (with e.g. KASAN enabled)?

We are using the [build_release.sh script](./build_release.sh) script to build new releases, but this does not work retroactively because it uses the latest config.

The exact `.config` can be found at `https://storage.googleapis.com/kernelctf-build/releases/<release_name>/.config` where `<release_name>` is e.g. `lts-6.12.56`.

The exact repo and commit hash is in `https://storage.googleapis.com/kernelctf-build/releases/<release_name>/COMMIT_INFO`.

The repo needs to be checked out and then the `.config` put into the source directory and then the kernel can be built with `make -j$(nproc)`.
