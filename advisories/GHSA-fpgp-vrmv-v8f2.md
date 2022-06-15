---
title: ' Zoom: XSS in Zoom.us Signup Flow'
severity: High
ghsa_id: GHSA-fpgp-vrmv-v8f2
cve_id: ''
weaknesses: []
products:
- ecosystem: ''
  package_name: zoom.us
  affected_versions: <2020.04.08
  patched_versions: 2020.07.07
cvss: null
credits:
- github_user_id: totallyunknown
  name: Nils Juenemann
  avatar: https://avatars.githubusercontent.com/u/1724494?s=40&v=4
- github_user_id: sirdarckcat
  name: Eduardo' Vela" <Nava> (sirdarckcat)
  avatar: https://avatars.githubusercontent.com/u/33089?s=40&v=4
---

## Summary

Zoom.us did not sanitize the name of the user on the federated signup flow. This allowed an attacker to execute arbitrary JavaScript on a victim's browser in the context of https://zoom.us/ when opening a malicious link.

## Severity
Calculated as **High** by Google ([source](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L/E:P/RL:O/RC:C)). The attacker needs to convince a victim to visit a malicious link, then the exploit can log the victim back in as the real user, and gain access to the victim's Zoom.us account. This could allow an attacker to do anything the victim can do through the website.

## Proof of Concept

The victim had to visit a URL of the form: `https://zoom.us/signin/term?token=...&type=2`.

In order to construct such a URL, the attacker had to:

1. Visit the following URL while being logged-in with the attacker's account (the attacker's account needs to have the xss payload on its name): `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&access_type=offline&client_id=849883241272-ed6lnodi1grnoomiuknqkq2rbvd2udku.apps.googleusercontent.com&scope=profile%20email&redirect_uri=https%3A%2F%2Fzoom.us%2Fgoogle%2Foauth&state=https%3A%2F%2Fzoom.us%2Fgoogle%2Foauth`
2. That URL would then redirect to: `https://zoom.us/google/oauth?state=https%3A%2F%2Fzoom.us%2Fgoogle%2Foauth&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&code=..CODE..`
3. That URL would then redirect to `https://zoom.us/signin/term?token=...TOKEN..&type=2`

The last URL in step (3) could then be sent to unsuspecting victims, which would then trigger the XSS.

## Additional Analysis

### OAuth flow

Usually an attack like this would be prevented by a CSRF token in the state parameter of the OAuth web flow, but Zoom.us did not contain any unpredictable tokens, so exploitation was straightforward.

### User interaction

If the victim was an active Zoom.us user, then the attack required no user interaction. If the victim was not an active Zoom user, then the victim had to pass the "age check" before the XSS could trigger.

![Screenshot 2020-07-10 at 09 23 33](https://user-images.githubusercontent.com/33089/87127925-1106ed80-c28f-11ea-8c42-cab03d4dc674.png)

### XSS payload in name

To put a payload in a Google account name an attacker can use a [service account](https://developers.google.com/identity/protocols/oauth2/service-account), a premium GSuite account through an API, or a legacy GMail account.

The proof of concept provided to Zoom used GSuite.
![Screenshot 2020-04-08 at 09 50 48](https://user-images.githubusercontent.com/33089/86800154-02dc8580-c073-11ea-8651-0a7a90bd08ca.png)


@totallyunknown provided a screenshot with a legacy GMail account.
![xss payload screenshot](https://user-images.githubusercontent.com/33089/86798853-8bf2bd00-c071-11ea-9498-e9d186aa2e79.png)