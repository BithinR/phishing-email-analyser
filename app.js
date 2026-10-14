/* ============================================================
   Phishing Email Analyser — detection & scoring logic.
   Everything here runs locally in the visitor's browser.
   No data is ever sent anywhere.
   ============================================================ */

'use strict';

/* ------------------------------------------------------------
   Indicator definitions.
   Each indicator = a warning sign we look for. It has a label,
   how many points it adds to the score, a severity level, and a
   plain-English description shown to the user.
   ------------------------------------------------------------ */
const INDICATORS = {
  urgency: {
    label: 'Urgency / pressure language',
    points: 8,
    sev: 'medium',
    desc: 'Phishing often creates a false sense of urgency so you act before thinking. Words like "immediately", "within 24 hours" or "act now" are a classic pressure tactic.'
  },
  account_threat: {
    label: 'Threat of account suspension or closure',
    points: 12,
    sev: 'high',
    desc: 'Threatening to suspend, lock or close your account is a scare tactic used to push you into clicking a link or handing over your details.'
  },
  credential_harvesting: {
    label: 'Credential-harvesting language',
    points: 15,
    sev: 'high',
    desc: 'The message tries to get you to log in or "verify" your account through a link that may be fake, aiming to steal your username and password.'
  },
  request_password: {
    label: 'Asks for your password',
    points: 18,
    sev: 'critical',
    desc: 'A legitimate service will never ask you to send your password by email. Being asked for a password is a major red flag.'
  },
  request_code: {
    label: 'Asks for a verification / one-time code',
    points: 18,
    sev: 'critical',
    desc: 'One-time and verification codes should never be shared with anyone. Someone asking you to send a code back is trying to take over your account.'
  },
  gift_card: {
    label: 'Requests payment or gift cards',
    points: 15,
    sev: 'high',
    desc: 'Requests for payment by gift cards, wire transfer or cryptocurrency are almost always scams, because they are hard to trace and impossible to reverse.'
  },
  bank_change: {
    label: 'Asks to change bank / payment details',
    points: 20,
    sev: 'critical',
    desc: 'Asking you to change bank or payment details is a hallmark of Business Email Compromise (BEC) fraud, where payments are diverted to a scammer.'
  },
  invoice: {
    label: 'Unexpected invoice language',
    points: 8,
    sev: 'medium',
    desc: 'Unexpected invoices or payment demands are often used to trick people into paying fraudsters or opening malicious attachments.'
  },
  impersonation: {
    label: 'Impersonation language',
    points: 10,
    sev: 'medium',
    desc: 'The message claims to be from a trusted person or team (IT, support, a bank). Always check the real sender, not the name they claim.'
  },
  generic_greeting: {
    label: 'Generic greeting (weak signal)',
    points: 4,
    sev: 'low',
    desc: 'Greetings like "Dear customer" can indicate a mass-mailed message rather than one written for you personally. This is only a weak signal.'
  },
  suspicious_url: {
    label: 'Suspicious URL',
    points: 12,
    sev: 'high',
    desc: 'A link points to a domain containing deceptive words (like "login", "verify" or "secure") or a look-alike of a well-known brand.'
  },
  shortened_url: {
    label: 'Shortened URL',
    points: 8,
    sev: 'medium',
    desc: 'Shortened links (bit.ly, tinyurl, etc.) hide the real destination, so you cannot see where they will actually take you.'
  },
  ip_url: {
    label: 'URL using a raw IP address',
    points: 15,
    sev: 'high',
    desc: 'A link that goes straight to a numeric IP address instead of a normal domain is unusual for a legitimate business.'
  },
  misleading_link: {
    label: 'Misleading link text',
    points: 12,
    sev: 'high',
    desc: 'The text you see for the link says one thing, but the real destination is a different website.'
  },
  http_login: {
    label: 'Sign-in link over insecure HTTP',
    points: 10,
    sev: 'medium',
    desc: 'A link asking you to sign in uses insecure HTTP (not HTTPS), so anything you type could be intercepted in transit.'
  },
  suspicious_attachment: {
    label: 'Suspicious attachment filename',
    points: 10,
    sev: 'high',
    desc: 'The attachment is an unusual or risky file type (such as a compressed archive or a double extension), a common way to deliver malware.'
  },
  executable_attachment: {
    label: 'Executable attachment type',
    points: 18,
    sev: 'critical',
    desc: 'The attachment is an executable or macro-enabled file. Opening it could install malware on your device.'
  },
  enable_macros: {
    label: 'Requests enabling macros',
    points: 18,
    sev: 'critical',
    desc: 'Asking you to "enable macros" or "enable content" on a document is a classic malware-delivery trick.'
  },
  sender_reply_mismatch: {
    label: 'Sender / Reply-To mismatch',
    points: 10,
    sev: 'high',
    desc: 'The "From" address and "Reply-To" address are different. Your reply may go to a scammer instead of the real sender.'
  },
  spf_fail: {
    label: 'SPF authentication failure',
    points: 10,
    sev: 'high',
    desc: 'SPF failed, meaning the sending server was not authorised by the claimed sender\'s domain. The sender may be spoofed.'
  },
  dkim_fail: {
    label: 'DKIM authentication failure',
    points: 10,
    sev: 'high',
    desc: 'DKIM failed, meaning the email\'s signature did not verify. Its content may have been altered or forged.'
  },
  dmarc_fail: {
    label: 'DMARC authentication failure',
    points: 12,
    sev: 'high',
    desc: 'DMARC failed, meaning the email failed the domain\'s anti-spoofing policy checks.'
  }
};

/* ------------------------------------------------------------
   Word and phrase patterns used to detect each text indicator.
   Matching is case-insensitive.
   ------------------------------------------------------------ */
const PHRASES = {
  urgency: [
    'urgent', 'immediately', 'act now', 'as soon as possible', 'asap', 'without delay',
    'right away', 'limited time', 'final warning', 'final notice', 'last warning',
    'expires today', 'expires in', 'within 24 hours', 'within 12 hours', 'within 48 hours',
    'deadline', 'do not ignore', 'action required', 'urgent action', 'time sensitive',
    'time-sensitive', 'hours to respond', 'immediate attention', 'do not delay', 'don\'t delay'
  ],
  account_threat: [
    'account will be suspended', 'account suspension', 'account will be closed',
    'account has been suspended', 'account has been disabled', 'account disabled',
    'account deactivated', 'account will be deactivated', 'account has been compromised',
    'suspend your account', 'will be suspended', 'terminate your account', 'your account will be terminated',
    'permanently closed', 'access will be terminated', 'mailbox will be closed',
    'deactivate your account', 'account has been locked', 'lock your account',
    'close your account', 'your account is at risk'
  ],
  credential_harvesting: [
    'verify your account', 'confirm your account', 're-activate your account',
    'reactivate your account', 're-validate', 'revalidate your account', 'update your account',
    'unlock your account', 'sign in to continue', 'log in to verify', 'confirm your identity',
    'verify your identity', 'keep your account active', 'confirm your email address',
    'validate your mailbox', 'mailbox verification', 'your account has been flagged',
    'keep your mailbox', 'upgrade your mailbox', 'secure your account', 'to avoid deactivation',
    'to keep your account'
  ],
  request_password: [
    'your password', 'enter your password', 'provide your password', 'confirm your password',
    'verify your password', 'update your password', 'send your password', 'submit your password',
    'password must be', 'login credentials', 'sign-in credentials', 'sign in credentials',
    'username and password', 'user name and password', 'email password', 'webmail password',
    'your login details', 'enter your credentials'
  ],
  request_code: [
    'verification code', 'one-time code', 'one time code', 'security code',
    'authentication code', '6-digit code', 'six-digit code', 'one time password',
    'one-time password', 'mfa code', '2fa code', 'two-factor code', 'confirmation code',
    'send us the code', 'email us the code', 'read me the code', 'share the code',
    'code to complete', 'multi-factor authentication code', 'text us the code', 'the code will expire'
  ],
  gift_card: [
    'gift card', 'giftcard', 'gift cards', 'itunes', 'google play card', 'google play gift',
    'amazon gift', 'steam card', 'apple gift card', 'voucher', 'wire transfer',
    'send payment', 'make a payment', 'pay now', 'payment required', 'outstanding balance',
    'immediate payment', 'bitcoin', 'cryptocurrency', 'western union', 'moneygram',
    'apple pay', 'cash app', 'zelle'
  ],
  bank_change: [
    'change your bank details', 'update your bank details', 'new bank account',
    'change the payment details', 'update your payment details', 'bank details have changed',
    'updated bank account', 'revised banking details', 'bank account number', 'sort code',
    'account and routing number', 'new payment instructions', 'change of bank',
    'updated payment details', 'banking details'
  ],
  invoice: [
    'invoice', 'past due', 'overdue', 'outstanding invoice', 'invoice attached',
    'payment overdue', 'amount due', 'purchase order', 'proforma invoice', 'remittance',
    'statement of account', 'balance due', 'payment is due', 'attached invoice'
  ],
  impersonation: [
    'security team', 'support team', 'it department', 'help desk', 'helpdesk', 'service desk',
    'admin team', 'account team', 'fraud department', 'billing department', 'customer service',
    'webmail administrator', 'email administrator', 'system administrator', 'mail administrator',
    'we detected', 'unusual activity', 'suspicious activity', 'on behalf of', 'representative',
    'card issuer', 'the management', 'our records show'
  ],
  generic_greeting: [
    'dear customer', 'dear user', 'dear client', 'dear valued', 'dear account holder',
    'dear member', 'hello user', 'attention customer', 'dear email user', 'dear subscriber',
    'valued customer', 'dear team member'
  ],
  enable_macros: [
    'enable macros', 'enable content', 'enable editing', 'macros must be enabled',
    'content must be enabled', 'click enable content', 'enable editing to view',
    'turn on macros', 'enable macro'
  ]
};

/* ------------------------------------------------------------
   URL-related constants.
   ------------------------------------------------------------ */
const SHORTENER_DOMAINS = [
  'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'lnkd.in', 'adf.ly', 's.id', 'j.mp',
  'qr.ae', 'bit.do', 'clck.ru', 'href.li', 'x.co', 't.ly', 'v.gd', 'soo.gd', 'mcaf.ee', 'tr.im'
];

const BRAND_NAMES = [
  'microsoft', 'office365', 'outlook', 'apple', 'icloud', 'google', 'gmail', 'paypal',
  'amazon', 'netflix', 'dropbox', 'linkedin', 'facebook', 'instagram', 'whatsapp', 'ebay',
  'adobe', 'zoom', 'slack', 'github', 'dhl', 'fedex', 'ups', 'usps', 'royalmail'
];

const LEGIT_DOMAINS = [
  'microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'live.com',
  'outlook.com', 'onedrive.com', 'google.com', 'gmail.com', 'googlemail.com', 'youtube.com',
  'apple.com', 'icloud.com', 'amazon.com', 'paypal.com', 'linkedin.com', 'facebook.com',
  'instagram.com', 'dropbox.com', 'netflix.com', 'ebay.com', 'adobe.com', 'zoom.us',
  'slack.com', 'github.com', 'dhl.com', 'fedex.com', 'ups.com', 'usps.com', 'royalmail.com',
  'example.com', 'example.org', 'example.net'
];

const DECEPTIVE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security', 'account',
  'update', 'confirm', 'auth', 'billing', 'wallet', 'banking', 'webscr', 'validate',
  'unlock', 'recovery', 'password', 'alert', 'suspended', 'suspension', 'official',
  'tracking', 'track', 'parcel', 'delivery', 'invoice', 'payment'
];

const DECEPTIVE_LOGIN_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'secure', 'account', 'confirm', 'auth', 'password', 'banking'
];

const EXEC_EXT = [
  'exe', 'scr', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'ps1', 'msi', 'msp',
  'jar', 'reg', 'hta', 'cpl', 'wsf', 'wsh', 'pif', 'apk', 'dll', 'lnk', 'url',
  'docm', 'xlsm', 'pptm', 'dotm', 'xltm'
];

const ARCHIVE_EXT = ['zip', 'rar', '7z', 'iso', 'img', 'tgz', 'gz', 'tar', 'bz2'];

/* ------------------------------------------------------------
   Small helpers.
   ------------------------------------------------------------ */
function isLegitDomain(host) {
  return LEGIT_DOMAINS.some(function (d) {
    return host === d || host.endsWith('.' + d);
  });
}

function isSuspiciousHost(host) {
  if (isLegitDomain(host)) return false;
  var lower = host.toLowerCase();
  if (DECEPTIVE_KEYWORDS.some(function (k) { return lower.indexOf(k) !== -1; })) return true;
  if (BRAND_NAMES.some(function (b) { return lower.indexOf(b) !== -1; })) return true;
  return false;
}

function parseHost(url) {
  try {
    var u = new URL(url.indexOf('www.') === 0 ? 'http://' + url : url);
    return { protocol: u.protocol, hostname: u.hostname.toLowerCase() };
  } catch (e) {
    return null;
  }
}

function looksLikeUrlOrDomain(s) {
  var t = s.trim();
  if (/^https?:\/\//i.test(t) || /^www\./i.test(t)) return true;
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) return true;
  return false;
}

/* ------------------------------------------------------------
   Extract URLs from text (plain links, Markdown and HTML links).
   ------------------------------------------------------------ */
function extractUrls(text) {
  var results = [];
  var seen = {};

  function consider(rawUrl, displayText) {
    var raw = rawUrl.trim().replace(/[.,;:!?)\]]+$/, '');
    var parsed = parseHost(raw);
    if (!parsed) return;
    if (seen[raw]) return;
    seen[raw] = true;
    var host = parsed.hostname;
    var isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    var isShort = SHORTENER_DOMAINS.some(function (d) { return host === d || host.endsWith('.' + d); });
    var suspicious = isSuspiciousHost(host);
    var isHttpLogin = parsed.protocol === 'http:' &&
      DECEPTIVE_LOGIN_KEYWORDS.some(function (k) { return host.indexOf(k) !== -1; });
    var isMisleading = false;
    if (displayText && looksLikeUrlOrDomain(displayText)) {
      var dHost = parseHost(displayText);
      if (dHost && dHost.hostname !== host) isMisleading = true;
    }
    results.push({
      raw: raw, hostname: host, isShort: isShort, isIp: isIp,
      suspicious: suspicious, isHttpLogin: isHttpLogin, isMisleading: isMisleading,
      displayText: displayText
    });
  }

  var md = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/gi;
  var m;
  while ((m = md.exec(text))) consider(m[2], m[1]);

  var html = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  while ((m = html.exec(text))) consider(m[1], m[2].replace(/<[^>]*>/g, '').trim());

  var plain = /(?:https?:\/\/|www\.)[^\s<>"'()\[\]]+/gi;
  while ((m = plain.exec(text))) consider(m[0], null);

  return results;
}

/* ------------------------------------------------------------
   Attachment filename detection.
   ------------------------------------------------------------ */
function findFilenames(text) {
  var files = [];
  var re = /\b[a-z0-9][\w\-.]{1,80}\.[a-z0-9]{2,5}\b/gi;
  var m;
  var seen = {};
  while ((m = re.exec(text))) {
    var name = m[0];
    var lower = name.toLowerCase();
    if (seen[lower]) continue;
    seen[lower] = true;
    if (/https?:|www\.|@/.test(lower)) continue;
    var parts = lower.split('.');
    var ext = parts[parts.length - 1];
    var secondLast = parts.length >= 3 ? parts[parts.length - 2] : '';
    var doubleExt = parts.length >= 3 && secondLast.length >= 2 && secondLast.length <= 5 &&
      !/[^a-z0-9]/.test(secondLast);
    files.push({ name: name, ext: ext, doubleExt: doubleExt });
  }
  return files;
}

/* ------------------------------------------------------------
   Header-based checks (SPF / DKIM / DMARC / sender vs Reply-To).
   ------------------------------------------------------------ */
function checkHeaders(text, add) {
  var lower = text.toLowerCase();
  if (/\bspf\s*=\s*(fail|softfail)\b/.test(lower)) add('spf_fail', ['SPF authentication failed']);
  if (/\bdkim\s*=\s*fail\b/.test(lower)) add('dkim_fail', ['DKIM signature invalid']);
  if (/\bdmarc\s*=\s*fail\b/.test(lower)) add('dmarc_fail', ['DMARC policy check failed']);

  var fromLine = (text.match(/^from\s*:\s*(.+)$/mi) || [])[1];
  var replyLine = (text.match(/^reply-to\s*:\s*(.+)$/mi) || [])[1];
  if (fromLine && replyLine) {
    var fDom = domainFrom(fromLine);
    var rDom = domainFrom(replyLine);
    if (fDom && rDom && fDom !== rDom) {
      add('sender_reply_mismatch', ['From: ' + fDom + ' / Reply-To: ' + rDom]);
    }
  }
}

function domainFrom(headerValue) {
  var m = String(headerValue).match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i);
  return m ? m[1].toLowerCase() : null;
}

/* ------------------------------------------------------------
   Main analysis: detect everything and sum the score.
   ------------------------------------------------------------ */
function runAnalysis(rawText) {
  var lower = rawText.toLowerCase();
  var found = {}; // id -> { meta, evidence: [] }

  function add(id, evidenceItems) {
    if (!found[id]) found[id] = { meta: INDICATORS[id], evidence: [] };
    evidenceItems.forEach(function (e) {
      if (found[id].evidence.indexOf(e) === -1) found[id].evidence.push(e);
    });
  }

  // 1. Text / phrase checks
  Object.keys(PHRASES).forEach(function (id) {
    var hits = PHRASES[id].filter(function (p) { return lower.indexOf(p) !== -1; });
    if (hits.length) add(id, hits);
  });
  if (/\botp\b/.test(lower)) add('request_code', ['otp']);

  // 2. URL checks
  var urls = extractUrls(rawText);
  urls.forEach(function (u) {
    if (u.isShort) add('shortened_url', [u.raw]);
    if (u.isIp) add('ip_url', [u.raw]);
    if (u.suspicious) add('suspicious_url', [u.hostname]);
    if (u.isHttpLogin) add('http_login', [u.raw]);
    if (u.isMisleading) add('misleading_link', [u.displayText + ' \u2192 ' + u.raw]);
  });

  // 3. Attachment checks
  var urlStrings = urls.map(function (u) { return u.raw; });
  var body = stripUrls(rawText, urlStrings);
  var files = findFilenames(body);
  files.forEach(function (f) {
    if (EXEC_EXT.indexOf(f.ext) !== -1) add('executable_attachment', [f.name]);
    else if (ARCHIVE_EXT.indexOf(f.ext) !== -1 || f.doubleExt) add('suspicious_attachment', [f.name]);
  });

  // 4. Header checks
  checkHeaders(rawText, add);

  // Build ordered findings list (same order as INDICATORS)
  var order = Object.keys(INDICATORS);
  var findings = [];
  order.forEach(function (id) {
    if (found[id]) {
      findings.push({
        id: id,
        label: found[id].meta.label,
        points: found[id].meta.points,
        sev: found[id].meta.sev,
        desc: found[id].meta.desc,
        evidence: found[id].evidence
      });
    }
  });

  var score = findings.reduce(function (sum, f) { return sum + f.points; }, 0);
  if (score > 100) score = 100;

  return {
    score: score,
    classification: classify(score),
    findings: findings,
    recommendations: buildRecommendations(findings, score)
  };
}

function stripUrls(text, urlStrings) {
  var out = text;
  urlStrings.forEach(function (u) {
    out = out.split(u).join(' ');
  });
  return out;
}

/* ------------------------------------------------------------
   Classification bands.
   ------------------------------------------------------------ */
function classify(score) {
  if (score >= 60) {
    return {
      key: 'high', label: 'High Risk', color: '#ef4444',
      blurb: 'This message shows many serious warning signs. Do not click any links, open attachments, or provide information. Verify through official channels if needed.'
    };
  }
  if (score >= 25) {
    return {
      key: 'suspicious', label: 'Suspicious', color: '#f59e0b',
      blurb: 'This message shows several warning signs. Treat it with caution and verify anything it asks for through official channels before acting.'
    };
  }
  return {
    key: 'low', label: 'Low Risk', color: '#22c55e',
    blurb: 'This message shows few or no warning signs. It still cannot be guaranteed safe \u2014 stay alert and verify anything important.'
  };
}

/* ------------------------------------------------------------
   Recommendations based on what was found.
   ------------------------------------------------------------ */
function buildRecommendations(findings, score) {
  var ids = {};
  findings.forEach(function (f) { ids[f.id] = true; });

  var recs = [];
  recs.push('Do not click any links or open any attachments in this message.');
  recs.push('Verify the request independently using the organisation\'s official website, app, or a phone number you already trust \u2014 never using contact details provided in the email.');
  recs.push('Do not reply with passwords, verification codes, or financial information.');

  if (ids.request_password || ids.request_code || ids.credential_harvesting) {
    recs.push('If you already entered a password or shared a code, change your password immediately on the official website and enable multi-factor authentication (MFA).');
  }
  if (ids.bank_change || ids.gift_card || ids.invoice) {
    recs.push('Never change payment or bank details based on an email alone \u2014 phone the supplier or person using a number from your own records to confirm.');
  }
  if (ids.executable_attachment || ids.suspicious_attachment) {
    recs.push('Do not open attachments you were not expecting. If it seems important, confirm with the sender through a separate channel first.');
  }
  if (ids.enable_macros) {
    recs.push('Never enable macros or "enable content" on a document you were not expecting \u2014 this is a common way malware is delivered.');
  }
  if (ids.spf_fail || ids.dkim_fail || ids.dmarc_fail) {
    recs.push('The email failed authentication checks (SPF/DKIM/DMARC), so it may not genuinely be from the sender it claims to be. Treat it with extra caution.');
  }
  if (ids.suspicious_url || ids.shortened_url || ids.ip_url || ids.misleading_link || ids.http_login) {
    recs.push('Treat all links as unsafe. Instead of clicking, open the service by typing its address yourself or using your bookmarks/app.');
  }
  if (score < 25) {
    recs.push('This email shows few warning signs, but always stay alert and verify anything important through official channels.');
  }
  recs.push('If this arrived at work or school, report it to your IT / security team.');

  return recs;
}

/* ------------------------------------------------------------
   Rendering: turn the analysis result into HTML on the page.
   ------------------------------------------------------------ */
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

var SEV_LABEL = { low: 'Weak', medium: 'Moderate', high: 'Strong', critical: 'Critical' };

function renderResults(result) {
  var wrap = document.getElementById('results');
  var empty = document.getElementById('emptyState');
  var c = result.classification;
  var findings = result.findings;

  var findingsHtml;
  if (findings.length === 0) {
    findingsHtml = '<div class="no-findings">\u2705 No warning signs detected.</div>';
  } else {
    findingsHtml = '<ul class="findings">' + findings.map(function (f) {
      var ev = '';
      if (f.evidence && f.evidence.length) {
        var codes = f.evidence.slice(0, 4).map(function (e) {
          return '<code>' + escapeHtml(e) + '</code>';
        }).join(' ');
        ev = '<div class="finding-evidence"><span>Detected:</span> ' + codes + '</div>';
      }
      return '<li class="finding">' +
        '<div class="finding-head">' +
          '<span class="sev sev-' + f.sev + '">' + (SEV_LABEL[f.sev] || f.sev) + '</span>' +
          '<span class="finding-name">' + escapeHtml(f.label) + '</span>' +
          '<span class="finding-points">+' + f.points + '</span>' +
        '</div>' +
        '<p class="finding-desc">' + escapeHtml(f.desc) + '</p>' +
        ev +
      '</li>';
    }).join('') + '</ul>';
  }

  var recsHtml = '<ul class="recs">' + result.recommendations.map(function (r) {
    return '<li>' + escapeHtml(r) + '</li>';
  }).join('') + '</ul>';

  wrap.innerHTML =
    '<div class="result-hero">' +
      '<div class="gauge" style="--val:' + result.score + ';--color:' + c.color + ';" aria-hidden="true">' +
        '<div class="gauge-inner"><span class="score">' + result.score + '</span>' +
        '<span class="score-label">/ 100</span></div>' +
      '</div>' +
      '<div class="result-summary">' +
        '<div class="classification" style="--c:' + c.color + ';">' + escapeHtml(c.label) + '</div>' +
        '<p class="summary-text">' + escapeHtml(c.blurb) + '</p>' +
        '<p class="score-note">This score is the sum of the points for each warning sign found, capped at 100. It is a heuristic, <strong>not</strong> a probability or a guarantee.</p>' +
      '</div>' +
    '</div>' +
    '<section class="card">' +
      '<div class="card-head"><h2>Warning signs found</h2><span class="count">' + findings.length + '</span></div>' +
      findingsHtml +
    '</section>' +
    '<section class="card">' +
      '<h2>What to do next</h2>' +
      recsHtml +
    '</section>' +
    '<p class="result-disclaimer">Remember: this is an educational tool. It cannot say for certain whether this email is safe or malicious. When in doubt, verify through official channels and do not click links or open attachments.</p>';

  empty.hidden = true;
  wrap.hidden = false;
  wrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ------------------------------------------------------------
   Fictional demonstration emails.
   These use only made-up domains (the reserved .example TLD and
   documentation IP ranges), so none of them can point anywhere real.
   ------------------------------------------------------------ */
const DEMOS = {
  obvious: `Subject: CONGRATULATIONS!! You have won $1,000,000 USD

Dear Customer,

You have been selected as the winner of our international lottery! To claim your prize you must act now. This offer expires in 24 hours, so do not ignore this message.

To receive your funds, you need to send a $250 processing fee using iTunes gift cards. Buy the gift cards and send us the code immediately.

Please download the attached claim form and fill in your details:
Attachment: CLAIM_FORM.exe

You can also claim online right now at:
[www.microsoft.com](http://192.0.2.45/claim/verify)

Congratulations once again!
International Lottery Claims Team`,

  sophisticated: `From: IT Security <security@contoso-secure.example>
Reply-To: security@contoso.example.net
Authentication-Results: mail.example.com; spf=fail smtp.mailfrom=contoso-secure.example
Authentication-Results: mail.example.com; dkim=fail reason="signature invalid"
Authentication-Results: mail.example.com; dmarc=fail header.from=contoso-secure.example
Subject: Required: verify your account access

Dear valued employee,

We are writing to let you know that our security team detected unusual activity on your corporate account. To keep your account active and avoid any interruption to your access, please verify your account within 24 hours.

You can verify by signing in through the employee portal below:

[Contoso Employee Portal](https://login.contoso.example/verify-account)

If you do not verify your account, it will be suspended as a precaution.

This is an automated message from the IT department.

IT Security Team`,

  microsoft: `From: Microsoft Account Team <no-reply@microsoft-account-alert.example>
Subject: Unusual sign-in detected on your Microsoft 365 account

Dear Customer,

We detected unusual sign-in activity on your Microsoft 365 account from a new device. For your security, your account has been locked and will be closed in 24 hours unless you verify your identity immediately.

Please sign in to confirm your account and re-activate your mailbox:
[Confirm my account](https://login.microsoft-365-verify.example/signin)

You will need to enter your password and the 6-digit verification code we send to you.

If you don't take action, your mailbox will be permanently closed.

Thank you,
Microsoft Account Security Team`,

  parcel: `From: Delivery Services <noreply@parcel-track.example>
Subject: Your package could not be delivered

Dear Customer,

We attempted to deliver your parcel today but no one was available. Your package is being held at our depot and will be returned to sender within 48 hours if no action is taken.

To arrange redelivery, a small re-delivery fee of $1.99 is required. Please pay now using the secure link below:

http://bit.ly/redelivery-fee

Enter your payment details and the confirmation code you receive to complete the redelivery.

Track your package here: https://parcel-track.example/track

Thank you,
Parcel Delivery Team`,

  invoice: `From: Sarah Chen <sarah@vendor-supplies.example>
Subject: Revised invoice and updated bank details

Hi,

Following our recent conversation, please find attached our latest invoice for the outstanding balance. This needs to be settled urgently before our end-of-month close.

Invoice_2024_SCAN.zip

Important: our bank details have changed. Please update your bank details and send payment to the new account below:

Account name: Vendor Supplies Ltd
Account number: 01234567
Sort code: 12-34-56

Please confirm once payment has been made so we can update our records.

Best regards,
Sarah Chen`,

  legit: `From: Priya Patel <priya.patel@example.com>
Reply-To: priya.patel@example.com
Subject: Team lunch on Friday

Hi team,

Just a reminder that we have our monthly team lunch this Friday at 12:30 in the cafeteria. Please let me know by Thursday if you can make it so I can book the table.

We'll also briefly go over next month's project timeline during lunch, so please bring any questions you have.

Thanks,
Priya`
};

/* ------------------------------------------------------------
   Wire up the page.
   ------------------------------------------------------------ */
function init() {
  var textarea = document.getElementById('emailText');
  var analyseBtn = document.getElementById('analyseBtn');
  var clearBtn = document.getElementById('clearBtn');
  var sample = document.getElementById('sample');
  var results = document.getElementById('results');
  var empty = document.getElementById('emptyState');

  function analyse() {
    var text = textarea.value.trim();
    if (!text) {
      results.hidden = true;
      empty.hidden = false;
      textarea.focus();
      return;
    }
    renderResults(runAnalysis(text));
  }

  analyseBtn.addEventListener('click', analyse);

  clearBtn.addEventListener('click', function () {
    textarea.value = '';
    sample.value = '';
    results.hidden = true;
    empty.hidden = false;
    textarea.focus();
  });

  sample.addEventListener('change', function () {
    var key = sample.value;
    if (!key || !DEMOS[key]) return;
    textarea.value = DEMOS[key];
    analyse();
  });
}

document.addEventListener('DOMContentLoaded', init);






