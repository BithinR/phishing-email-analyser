<div align="center">

# 🛡️ Phishing Email Analyser

**Learn to spot phishing — one warning sign at a time.**

*A privacy-first, browser-only educational tool that dissects suspicious emails and explains exactly what makes them dangerous.*

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Type-Static%20Web%20App-38bdf8?style=for-the-badge&labelColor=0b0f17" alt="Static web app" />
  <img src="https://img.shields.io/badge/Analysis-100%25%20In--Browser-22d3ee?style=for-the-badge&labelColor=0b0f17" alt="100% in-browser" />
  <img src="https://img.shields.io/badge/Privacy-No%20Data%20Leaves%20Device-22c55e?style=for-the-badge&labelColor=0b0f17" alt="No data leaves your device" />
  <img src="https://img.shields.io/badge/Stack-HTML%20%7C%20CSS%20%7C%20JS-404040?style=for-the-badge&labelColor=0b0f17" alt="HTML CSS JS" />
  <img src="https://img.shields.io/badge/Dependencies-None-22c55e?style=for-the-badge&labelColor=0b0f17" alt="No dependencies" />
  <img src="https://img.shields.io/badge/License-MIT-0366d6?style=for-the-badge&labelColor=0b0f17" alt="MIT" />
</p>

---

> ⚠️ **Educational triage tool — not a security product.** It can *never* say for certain
> whether an email is safe or malicious. It surfaces warning signs and gives you an
> explainable score. **Never click links or open attachments just to test them.**

## 📌 Project Overview

The Phishing Email Analyser is a lightweight, fully client-side web app that takes a
pasted email — including raw headers, if you have them — and returns:

- a **risk score from 0–100**,
- a **Low Risk / Suspicious / High Risk** classification,
- a **plain-English explanation of every warning sign** it found, and
- **practical recommendations** on what to do next.

Unlike most "email scanners", it uploads nothing. Every rule runs in plain JavaScript
inside the visitor's browser.

## 📸 Screenshot

<div align="center">

# ⬇️  SCREENSHOT PLACEHOLDER  ⬇️

**ADD A SCREENSHOT OF THE APP HERE**

*(Replace this section with: `![Phishing Email Analyser](screenshots/app.png)`)*

</div>

## 🎯 Why This Project?

Phishing is how most real-world breaches start — and it's a *human* problem, not just a
technical one. This project exists to:

- **Teach** the actual tactics attackers use (urgency, impersonation, credential
  harvesting, malicious links and attachments).
- **Prove** that a useful security-education tool can be built with plain HTML/CSS/JS —
  no backend, no data collection.
- **Demystify** risk scores by making every point traceable.

## ✨ Features

| Feature | What you get |
| --- | --- |
| 🎚️ Explainable scoring | No black box — every detected indicator is listed with its point value |
| 🧠 22 indicators | Urgency, threats, credential harvesting, financial requests, links, attachments, impersonation & headers |
| 🔍 Header-aware | Checks SPF / DKIM / DMARC results and `From` vs `Reply-To` when headers are pasted |
| 📧 Six sample emails | One-click fictional examples to explore instantly |
| 📱 Responsive UI | Dark security-dashboard look that works on desktop & mobile |
| 🔌 Works offline | No network calls — it keeps working after the page loads |

## 🧠 How the score works

```
score = min(100, sum of every detected indicator's points)
```

Each of the 22 indicators carries a fixed point value (mild signals score low, critical
ones score high). The total is capped at 100 and mapped to a band:

| Score | Classification |
| --- | --- |
| 0–24 | 🟢 Low Risk |
| 25–59 | 🟠 Suspicious |
| 60–100 | 🔴 High Risk |

### The 22 detection indicators

| # | Indicator | Points | Severity |
| --- | --- | ---: | --- |
| 1 | Urgency / pressure language | 8 | Medium |
| 2 | Threat of account suspension or closure | 12 | High |
| 3 | Credential-harvesting language | 15 | High |
| 4 | Asks for your password | 18 | Critical |
| 5 | Asks for a verification / one-time code | 18 | Critical |
| 6 | Requests payment or gift cards | 15 | High |
| 7 | Asks to change bank / payment details | 20 | Critical |
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

## 📧 Fictional sample emails

Six made-up examples are bundled so you can try it instantly. They all use the reserved
`.example` top-level domain and documentation IP ranges (`192.0.2.x`), so **none of them
can point to a real website**.

| Sample | Typical score | Result |
| --- | ---: | --- |
| Obvious phishing (lottery / gift card) | 90 | 🔴 High Risk |
| Sophisticated phishing (spoofed headers) | 100 | 🔴 High Risk |
| Fake Microsoft 365 account warning | 97 | 🔴 High Risk |
| Fake parcel-delivery message | 65 | 🔴 High Risk |
| Fake invoice / BEC | 61 | 🔴 High Risk |
| Legitimate email | 0 | 🟢 Low Risk |

## 🔐 Privacy & security (a core design goal)

| Promise | How it's guaranteed |
| --- | --- |
| No server | It's a static site — there's nothing to upload *to* |
| No tracking | No analytics, no beacons, no `<img>` tracking pixels |
| No external calls | The JavaScript makes zero network requests |
| No storage | Pasted text is never saved or cached |

There is simply **no code path** that can transmit your email. Open the page, go offline,
and it still works.

## 🚀 Quick start

No terminal, no build step, no install.

1. Download or clone this repository.
2. Open `index.html` in any modern web browser.

Done. 🎉

## 🗂️ Repository structure

```
phishing-email-analyser/
├── index.html      # Page structure, privacy notice, disclaimers
├── styles.css      # Appearance (dark theme, responsive)
├── app.js          # All detection & scoring logic (runs locally)
├── REPORT.md       # Full project report
├── LICENSE         # MIT license
└── README.md       # This file
```

## 🌐 Host it for free

This is a fully static site, so any static host works:

- **GitHub Pages** — Settings → Pages → deploy from `main`.
- **Netlify Drop** — drag the folder onto [netlify.com](https://netlify.com).
- **Cloudflare Pages** — connect the repository or upload the folder.

> Keep `index.html`, `styles.css` and `app.js` together in the same root.

## ⚖️ Safety & limitations

- It **cannot definitively determine** whether an email is malicious.
- It is **not** a replacement for email gateways, antivirus, or a security team.
- False positives and false negatives are expected.
- Users are warned **not** to click links or open attachments just to test them, and to
  verify important messages through official channels.

## 🔗 Resources

- [CISA — Recognize and Report Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [OWASP — Phishing](https://owasp.org/www-community/attacks/Phishing)
- [DMARC.org — Overview](https://dmarc.org/overview/)

## 👤 Author

**Bithin Krishna Radhakrishnan**
Cybersecurity enthusiast & independent learner

- GitHub: [github.com/BithinR](https://github.com/BithinR)
- LinkedIn: [linkedin.com/in/bkr95](https://www.linkedin.com/in/bkr95)

## 📄 License

Released under the [MIT License](LICENSE). Free to use, modify and share.


