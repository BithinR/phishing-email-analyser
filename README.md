# 🛡️ Phishing Email Analyser

A free, privacy-first, **educational** web app that analyses the text of a suspicious
email for common phishing and social-engineering warning signs — **entirely in the
visitor's browser**. No server, no database, no accounts, no tracking.

> ⚠️ **Educational triage tool only.** This project can *never* definitively tell you
> whether an email is safe or malicious. It looks for warning signs and gives you an
> explainable score to help you make a more informed decision. **Never click links or
> open attachments just to test them.**

<p align="center">
  <img src="https://img.shields.io/badge/type-static%20site-22c55e" alt="Static site" />
  <img src="https://img.shields.io/badge/backend-none-22c55e" alt="No backend" />
  <img src="https://img.shields.io/badge/analysis-100%25%20local-38bdf8" alt="100% local analysis" />
  <img src="https://img.shields.io/badge/no%20dependencies-22c55e" alt="No dependencies" />
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license" />
</p>

## What it does

Paste a suspicious email (including full headers if you have them) and click
**Analyse Email**. The tool then shows you:

- A **phishing risk score from 0–100**.
- A **classification**: Low Risk / Suspicious / High Risk.
- A **plain-English explanation of every warning sign** it found — including how many
  points each one added to the score and the exact text/link that triggered it.
- **Practical recommendations** on what to do next.

It detects 22 indicators across these categories:

| Category | Examples |
| --- | --- |
| Urgency & pressure | "act now", "within 24 hours", deadlines |
| Threats | account suspension, closure, lockout |
| Credential harvesting | "verify your account", "unlock your account" |
| Sensitive requests | passwords, one-time codes, MFA codes |
| Financial requests | gift cards, wire transfer, "change bank details" |
| Links | suspicious domains, shortened URLs, raw IP addresses, misleading link text, insecure HTTP login |
| Attachments | executables, macro-enabled files, archives, double extensions |
| Impersonation | "security team", "IT department", generic greetings |
| Email headers | SPF / DKIM / DMARC failures, sender vs Reply-To mismatch |

## Privacy (a core design goal)

- ✅ All analysis runs in **plain JavaScript inside the visitor's browser**.
- ✅ Email text is **never uploaded** to a server, AI provider, analytics service or API.
- ✅ **No tracking, no telemetry, no external requests.**
- ✅ It even works **offline** once the page has loaded.

## How the score works (no mystery numbers)

Every indicator contributes a **fixed number of points** (mild signals score low,
serious red flags score high). The app sums the points and caps the total at 100.
The results screen lists each detected indicator with its point value so you can
always see *why* the score is what it is. See
[`WRITEUP.md`](WRITEUP.md) for the full breakdown.

## Quick start (no terminal needed)

1. Download or clone this repository.
2. Open `index.html` in any modern web browser.

That's it. There is no build step and no install.

## Hosting it for free

This is a **fully static site** (plain HTML, CSS and JavaScript), so you can host it
for free anywhere static files are served:

- **GitHub Pages** — enable Pages on this repository (Settings → Pages → deploy from
  the main branch). The site is served from `index.html`.
- **Netlify Drop** — drag the folder onto [netlify.com](https://netlify.com).
- **Cloudflare Pages** — connect the repository or upload the folder.

> Note: `index.html`, `styles.css` and `app.js` must stay in the same folder/root.

## Fictional sample emails

Six made-up examples are bundled so you can try it instantly (from the dropdown):

1. Obvious phishing (lottery / gift-card scam)
2. Sophisticated phishing (with spoofed SPF/DKIM/DMARC headers)
3. Fake Microsoft 365 account warning
4. Fake parcel-delivery message
5. Fake invoice / Business Email Compromise (BEC)
6. Legitimate email

All use the reserved `.example` top-level domain and documentation IP ranges
(`192.0.2.x`), so none of them can point to a real website.

## Project structure

```
phishing-email-analyser/
├── index.html      # Page structure, privacy notice, disclaimers
├── styles.css      # Appearance (dark theme, responsive)
├── app.js          # All detection and scoring logic (runs locally)
├── WRITEUP.md      # Detailed project write-up / how it works
├── LICENSE         # MIT license
└── README.md       # This file
```

## Safety & accuracy

- This tool **cannot definitively determine** whether an email is malicious.
- It does **not** claim to be a security product.
- Users are warned **not** to click links or open attachments to "test" them.
- Users are advised to verify important messages using an organisation's official
  website, app, or known contact details.

## License

Released under the [MIT License](LICENSE). You are free to use, modify and share it.

