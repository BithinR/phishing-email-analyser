# Project Write-up: Phishing Email Analyser

**A privacy-first, browser-based tool for learning to spot phishing and social-engineering emails.**

---

## 1. Overview

The Phishing Email Analyser is a small, static web application that analyses the text
of an email and highlights the common techniques used in phishing and social-engineering
attacks. A user pastes an email (including its raw headers, if available), and the tool
returns:

- a **risk score from 0–100**,
- a **classification** (Low Risk, Suspicious or High Risk),
- an **explanation of every warning sign** detected, with the point value each one
  contributed, and
- **practical recommendations** on what to do next.

The defining constraint — and the most important design goal — is **privacy**: all
analysis happens locally in the visitor's browser. No email content is ever sent to a
server, an AI provider, an analytics service or any external API.

---

## 2. Why I built this

Phishing is the most common way real-world systems get compromised, and it is largely a
**human** problem rather than a purely technical one. I wanted a project that would let me
(and others) learn the actual *tactics* attackers use — urgency, impersonation, credential
harvesting, malicious links and attachments — in a safe, hands-on way.

I also wanted to prove a specific point: a useful, polished security-education tool can be
built with **plain HTML, CSS and JavaScript**, with no backend and no data collection.
Many "email scanners" upload your email to a server, which is exactly the opposite of what
you want when you are handling something sensitive. This tool demonstrates that
client-side analysis is a legitimate, privacy-preserving approach for this kind of triage.

## 3. Features

- **Explainable scoring** — no "black box". Every detected indicator is listed with its
  point contribution and the exact text or link that matched it.
- **22 indicators** across urgency, threats, credential harvesting, financial requests,
  links, attachments, impersonation and email-authentication headers.
- **Header-aware** — if raw headers are pasted, it checks SPF, DKIM and DMARC results and
  compares the `From` and `Reply-To` addresses.
- **Six fictional sample emails** so the tool can be explored with one click.
- **Fully responsive** dark UI that works on desktop and mobile.
- **Works offline** after the page has loaded, because nothing depends on the network.

## 4. Design principles

1. **Privacy first.** Email text must never leave the browser. No exceptions.
2. **Explainability.** The score must be a transparent sum of named, fixed point values.
3. **Honesty.** The tool must never claim certainty, and must warn users not to click
   links or open attachments just to test it.
4. **Simplicity.** Plain HTML/CSS/JS, no framework, no build step, no dependencies.
5. **Safety.** Bundled examples use only reserved domains and documentation IP ranges.

## 5. Architecture & technology choices

The app is three static files:

- `index.html` — structure, privacy notice, disclaimers.
- `styles.css` — a dark, responsive theme using CSS variables and a `conic-gradient`
  for the risk gauge.
- `app.js` — all logic: pattern lists, URL/attachment/header parsers, scoring, rendering.

**Why no framework?** A framework (like React) would add a build step and dependencies
for no benefit at this size, and would make the privacy story harder to reason about.
Everything here is readable, standard JavaScript that runs directly in the browser.

**Why no backend?** A backend would introduce a server that *could* log email content,
which is precisely what this project avoids. Keeping analysis client-side means privacy
is enforced *by design*, not by policy.

## 6. The scoring model

The score is deliberately **not** a machine-learning probability. It is a simple,
auditable sum:

```
score = min(100, sum of the point values of every detected indicator)
```

Each indicator has a fixed point value chosen by how serious the warning sign is
(roughly: mild 4–8, notable 8–12, strong 12–15, critical 18–20). The total is capped
at 100. The classification bands are:

| Score | Classification |
| --- | --- |
| 0–24 | Low Risk |
| 25–59 | Suspicious |
| 60–100 | High Risk |

Because every finding is shown with its point value, the user can always reconstruct the
number by hand. That is the opposite of a "mystery score".

### The 22 indicators

| # | Indicator | Points | Severity |
| --- | --- | ---: | --- |
| 1 | Urgency / pressure language | 8 | Medium |
| 2 | Threat of account suspension/closure | 12 | High |
| 3 | Credential-harvesting language | 15 | High |
| 4 | Asks for your password | 18 | Critical |
| 5 | Asks for a verification/one-time code | 18 | Critical |
| 6 | Requests payment or gift cards | 15 | High |
| 7 | Asks to change bank/payment details | 20 | Critical |
| 8 | Unexpected invoice language | 8 | Medium |
| 9 | Impersonation language | 10 | Medium |
| 10 | Generic greeting (weak signal) | 4 | Low |
| 11 | Suspicious URL | 12 | High |
| 12 | Shortened URL | 8 | Medium |
| 13 | URL using a raw IP address | 15 | High |
| 14 | Misleading link text | 12 | High |
| 15 | Sign-in link over insecure HTTP | 10 | Medium |
| 16 | Suspicious attachment filename | 10 | High |
| 17 | Executable attachment type | 18 | Critical |
| 18 | Requests enabling macros | 18 | Critical |
| 19 | Sender / Reply-To mismatch | 10 | High |
| 20 | SPF authentication failure | 10 | High |
| 21 | DKIM authentication failure | 10 | High |
| 22 | DMARC authentication failure | 12 | High |

## 7. How the detection works

Each indicator is a small, transparent rule rather than a "clever" model. This keeps the
tool easy to audit and easy to learn from.

- **Text / keyword rules** — the app matches case-insensitive phrases against the email
  body (for example `"act now"`, `"verify your account"`, `"change your bank details"`,
  `"enable macros"`). Each phrase belongs to exactly one indicator, so a match is easy to
  trace back.

- **URL rules** — the app extracts every link (plain URLs, Markdown `[text](url)` and
  HTML `<a href="…">`), then checks each one for:
  - **shortened domains** (`bit.ly`, `tinyurl.com`, …),
  - **raw IP addresses** (`http://192.0.2.45`),
  - **deceptive or look-alike domains** (hostnames containing words like `login`, `verify`
    or a known brand, unless it is the real, allow-listed domain),
  - **insecure HTTP on sign-in pages**, and
  - **misleading link text** (the visible text is a different domain from the real target).

- **Attachment rules** — the app looks for filename-like tokens and flags executable or
  macro-enabled extensions (`.exe`, `.scr`, `.js`, `.vbs`, `.docm`, …), archive files
  (`.zip`, `.rar`, …) and double extensions (`.pdf.exe`).

- **Header rules** — when raw headers are present, the app parses `Authentication-Results`
  lines for `spf=fail`, `dkim=fail` and `dmarc=fail`, and compares the domain in `From`
  against the domain in `Reply-To`.

A small **allow-list** of well-known legitimate domains (microsoft.com, google.com,
paypal.com, …) reduces false positives, so a genuine link to `login.microsoft.com` is not
flagged just because it contains the word "login".

## 8. Privacy by design

The strongest privacy guarantee comes from what the code *cannot* do. The JavaScript has:

- no `fetch()`/`XMLHttpRequest` calls,
- no `<img>`/beacon/analytics tags,
- no references to any external domain,
- no local persistence of pasted content.

There is simply no code path that can transmit the email text. A visitor can confirm this
by opening the browser's developer tools, loading the page, and then going offline — the
tool keeps working.

## 9. Safety & limitations

- The tool **cannot and does not** claim to definitively determine whether an email is
  malicious. It is a *triage* aid that surfaces warning signs.
- It is **not** a replacement for email gateways, antivirus, or a security team.
- False positives and false negatives are expected. A malicious email can look clean, and
  a harmless email can contain a phrase that trips a rule.
- Users are repeatedly warned not to click links or open attachments just to test them,
  and to verify important messages through official channels.

## 10. The fictional demo emails

The bundled samples exercise different parts of the engine and produce very different
results:

| Sample | Typical score | Result |
| --- | ---: | --- |
| Obvious phishing (lottery/gift card) | 90 | High Risk |
| Sophisticated phishing (spoofed headers) | 100 | High Risk |
| Fake Microsoft 365 warning | 97 | High Risk |
| Fake parcel delivery | 65 | High Risk |
| Fake invoice / BEC | 61 | High Risk |
| Legitimate email | 0 | Low Risk |

All samples use the reserved `.example` top-level domain and the documentation IP range
`192.0.2.x`, so none of the links resolve anywhere real.

## 11. Decisions & trade-offs

- **Keyword matching over machine learning.** Keyword rules are transparent and
  explainable, but they miss paraphrases and can false-positive. A future ML model could
  improve recall but would sacrifice the "every point is explainable" property.
- **Fixed point values.** This keeps the score auditable, but the exact values are
  somewhat arbitrary and could be tuned with real data.
- **A curated allow-list of domains.** This reduces false positives but is incomplete and
  must be maintained. It is a pragmatic compromise, not a definitive block-list.
- **`.com` was deliberately excluded** from the executable-extension list even though
  `.com` is a legacy executable type, because it is far more common as a top-level domain
  and caused false positives on domain names.

## 12. What I learned

- How phishing and social engineering work at a *pattern* level (urgency, authority,
  scarcity, credential and financial requests).
- How email authentication (SPF, DKIM, DMARC) is meant to stop spoofing — and why a
  "fail" in these headers is a meaningful signal.
- The value of **privacy-by-design**: making exfiltration *impossible* rather than merely
  prohibited.
- How to build a complete, polished, responsive UI with plain HTML/CSS/JS.

## 13. Future improvements

- Add **typo-squatting** detection (e.g. `paypa1.com`, `micosoft.com`) via edit distance.
- Detect **look-alike Unicode** characters in domains (homograph attacks).
- Add **optional** "explain this indicator" tooltips with real-world examples.
- Allow **tuning** of point values and adding custom rules.
- Add an **export/share** of the findings (still client-side only).
- Publish a **browser-extension** or **static hosted** version for one-click use.

## 14. References & further reading

- [CISA — Recognizing and Avoiding Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [OWASP — Phishing](https://owasp.org/www-community/attacks/Phishing)
- [DMARC.org — Overview](https://dmarc.org/overview/)
- [Google Transparency Report — Safe Browsing](https://transparencyreport.google.com/safe-browsing/overview)




