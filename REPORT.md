<div align="center">

# 📋 Phishing Email Analyser — Project Report

**Author:** Bithin Krishna Radhakrishnan
**Project type:** Independent cybersecurity learning project

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Type-Project%20Report-38bdf8?style=for-the-badge&labelColor=0b0f17" alt="Project report" />
  <img src="https://img.shields.io/badge/Status-Complete-22c55e?style=for-the-badge&labelColor=0b0f17" alt="Complete" />
  <img src="https://img.shields.io/badge/Domain-Cybersecurity%20Education-C00000?style=for-the-badge&labelColor=0b0f17" alt="Cybersecurity education" />
  <img src="https://img.shields.io/badge/Stack-HTML%20%7C%20CSS%20%7C%20JS-404040?style=for-the-badge&labelColor=0b0f17" alt="HTML CSS JS" />
</p>

---

## 1. Executive Summary

The **Phishing Email Analyser** is a browser-based educational tool that analyses the
text of a suspicious email and highlights the techniques commonly used in phishing and
social engineering. A user pastes an email — including its raw headers when available —
and the tool returns a **0–100 risk score**, a **Low Risk / Suspicious / High Risk**
classification, a **plain-English explanation of every warning sign** detected (with the
point value each contributed), and **practical recommendations**.

The defining constraint of the project is **privacy by design**: all analysis runs in
plain JavaScript inside the visitor's browser. No email content is ever transmitted to a
server, an AI provider, an analytics service or any external API.

## 2. Introduction & Motivation

Phishing remains the most common entry point for real-world compromises, and it exploits
people rather than software. I wanted a project that would let me learn the *specific
tactics* attackers rely on — urgency, impersonation, credential harvesting, malicious
links and attachments — in a safe, hands-on way.

The project also makes a deliberate point: a polished, useful security-education tool can
be built with **plain HTML, CSS and JavaScript**, with no backend and no data collection.
Many "email scanners" upload your email to a server, which is the opposite of what you
want when handling something sensitive. This tool demonstrates that client-side analysis
is a legitimate, privacy-preserving approach to triage.

## 3. Project Objectives

- Build a static, dependency-free web app that analyses email text for phishing indicators.
- Produce an **explainable** risk score where every point is traceable to a named rule.
- Detect indicators across urgency, threats, credential harvesting, financial requests,
  suspicious links, malicious attachments, impersonation and email-authentication headers.
- Guarantee that no email content leaves the visitor's browser.
- Provide a polished, responsive, professional-looking interface.

## 4. Scope & Ethics

- **All analysis is passive and local.** The tool performs no network activity of any kind.
- **All bundled samples are fictional** and use the reserved `.example` top-level domain
  and documentation IP ranges (`192.0.2.x`), so none can resolve to a real host.
- The tool is **strictly educational**. It is not intended to facilitate attacks, and it
  actively warns users not to click links or open attachments just to test them.

## 5. System Architecture

The application is a fully static site made of three files, with no build step:

```
+-------------------+      +-------------------+      +-------------------+
|     index.html    |      |     styles.css    |      |       app.js      |
|  structure & copy |  →   |  dark, responsive |  →   |  all logic, local |
+-------------------+      +-------------------+      +-------------------+
                     rendered entirely in the browser
                           (no network requests)
```

**Data flow**

1. The user pastes an email (or selects a fictional sample) into a `<textarea>`.
2. `runAnalysis(text)` runs a series of small, independent detectors.
3. Detected indicators are summed into a score (capped at 100).
4. `renderResults(result)` draws the gauge, classification, findings and recommendations.

**Why no framework?** A framework would add a build step and dependencies for no benefit
at this size, and would make the privacy story harder to reason about.

**Why no backend?** A backend would introduce a server that *could* log email content —
exactly what this project avoids. Keeping analysis client-side enforces privacy *by
design*, not by policy.

<div align="center">

# 📸  SCREENSHOT PLACEHOLDER  📸

**ADD A SCREENSHOT OF THE MAIN USER INTERFACE HERE**

*(e.g. `![Phishing Email Analyser — main screen](screenshots/main-screen.png)`)*

</div>

## 6. Technology Stack

| Layer | Choice | Rationale |
| --- | --- | --- |
| Markup | HTML5 | Semantic, dependency-free structure |
| Styling | CSS3 (custom properties, grid/flex, `conic-gradient`) | Dark theme without any CSS framework |
| Logic | Vanilla JavaScript (ES6+) | Runs natively in the browser |
| Storage | None | Nothing is persisted |
| Backend | None | Privacy by design |
| Dependencies | None | Zero packages, zero external requests |

## 7. The Scoring Model

The score is deliberately **not** a machine-learning probability. It is a transparent,
auditable sum:

```
score = min(100, sum of the point values of every detected indicator)
```

Each indicator has a fixed point value reflecting how serious the warning sign is
(roughly: mild 4–8, notable 8–12, strong 12–15, critical 18–20). The total is capped at
100 and mapped to a classification band:

| Score | Classification |
| --- | --- |
| 0–24 | 🟢 Low Risk |
| 25–59 | 🟠 Suspicious |
| 60–100 | 🔴 High Risk |

Because every finding is shown with its point value, the user can reconstruct the number
by hand. That is the opposite of a "mystery score".

## 8. Detection Methodology

Each indicator is a small, transparent rule rather than a "clever" model:

- **Text / keyword rules** — case-insensitive phrase matching against the email body
  (e.g. `"act now"`, `"verify your account"`, `"change your bank details"`,
  `"enable macros"`). Each phrase belongs to exactly one indicator.

- **URL rules** — every link (plain URLs, Markdown `[text](url)`, HTML `<a href="…">`) is
  extracted and checked for:
  - shortened domains (`bit.ly`, `tinyurl.com`, …),
  - raw IP addresses (`http://192.0.2.45`),
  - deceptive or look-alike domains (hostnames containing words like `login`, `verify` or
    a known brand, unless it is the real allow-listed domain),
  - insecure HTTP on sign-in pages,
  - misleading link text (visible text is a different domain from the real target).

- **Attachment rules** — filename-like tokens are flagged if they use executable or
  macro-enabled extensions (`.exe`, `.scr`, `.js`, `.vbs`, `.docm`, …), archive files
  (`.zip`, `.rar`, …) or double extensions (`.pdf.exe`).

- **Header rules** — when raw headers are present, `Authentication-Results` lines are
  parsed for `spf=fail`, `dkim=fail` and `dmarc=fail`, and the `From` domain is compared
  with the `Reply-To` domain.

A curated **allow-list** of well-known legitimate domains (microsoft.com, google.com,
paypal.com, …) reduces false positives, so a genuine `login.microsoft.com` link is not
flagged just for containing the word "login".

## 9. Indicator Catalogue

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

## 10. Test Results

The six bundled samples exercise different parts of the engine:

| Sample | Score | Result | Key indicators triggered |
| --- | ---: | --- | --- |
| Obvious phishing (lottery / gift card) | 90 | 🔴 High Risk | urgency, gift cards, code request, raw-IP link, misleading link, `.exe` |
| Sophisticated phishing (spoofed headers) | 100 | 🔴 High Risk | urgency, credential harvesting, impersonation, SPF/DKIM/DMARC fail, Reply-To mismatch |
| Fake Microsoft 365 warning | 97 | 🔴 High Risk | account threat, credential harvesting, password & code request, suspicious URL |
| Fake parcel delivery | 65 | 🔴 High Risk | urgency, payment request, code request, shortened & suspicious URL |
| Fake invoice / BEC | 61 | 🔴 High Risk | invoice, bank-detail change, payment request, archive attachment |
| Legitimate email | 0 | 🟢 Low Risk | *(none)* |

The legitimate sample scores zero, confirming the engine does not flag a normal message.

<div align="center">

# 📸  SCREENSHOT PLACEHOLDER  📸

**ADD SCREENSHOTS OF THE SAMPLE RESULTS HERE**

*(e.g. `![Result: High Risk](screenshots/result-high.png)`)*

</div>

## 11. Privacy & Data Handling

The strongest privacy guarantee comes from what the code **cannot** do:

- no `fetch()` / `XMLHttpRequest` calls,
- no analytics, beacons or tracking pixels,
- no references to any external domain,
- no local persistence of pasted content.

There is no code path that can transmit the email text. A visitor can confirm this by
opening the page, going offline, and watching the tool continue to work.

## 12. Limitations & Future Work

- **Keyword matching vs machine learning** — keyword rules are transparent and explainable
  but miss paraphrases and can false-positive. A future ML model could improve recall at
  the cost of the "every point is explainable" property.
- **Fixed point values** — keeps the score auditable, but the exact weights are somewhat
  arbitrary and could be tuned with real data.
- **Curated allow-list** — reduces false positives but is incomplete and must be maintained.
- **No verdict** — the tool intentionally never claims an email is definitively safe or
  malicious.

Planned improvements: typo-squatting detection, Unicode homograph detection, per-indicator
"explain this" tooltips, and an optional export of findings (still client-side).

## 13. Key Learnings

- How phishing and social engineering work at a *pattern* level (urgency, authority,
  scarcity, credential and financial requests).
- How SPF, DKIM and DMARC are meant to stop spoofing — and why a "fail" is meaningful.
- The value of **privacy by design**: making exfiltration *impossible* rather than merely
  prohibited.
- How to build a complete, polished, responsive UI with plain HTML/CSS/JS.

## 14. References

- [CISA — Recognize and Report Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [OWASP — Phishing](https://owasp.org/www-community/attacks/Phishing)
- [DMARC.org — Overview](https://dmarc.org/overview/)
- [Google Transparency Report — Safe Browsing](https://transparencyreport.google.com/safe-browsing/overview)

---

## 👤 Author

**Bithin Krishna Radhakrishnan**
Cybersecurity enthusiast & independent learner

- GitHub: [github.com/BithinR](https://github.com/BithinR)
- LinkedIn: [linkedin.com/in/bkr95](https://www.linkedin.com/in/bkr95)




