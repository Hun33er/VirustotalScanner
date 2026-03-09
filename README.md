# VT Scope Extractor

> A Burp Suite extension that extracts subdomains, domains, URLs, and IP addresses from VirusTotal API responses and lets you push them directly into Burp's Scope and Site Map.

---

## What It Does

When performing reconnaissance, VirusTotal domain reports contain a wealth of infrastructure data  subdomains, resolved IPs, detected and undetected URLs  that would otherwise require manual copy-pasting into Burp. This extension automates that entirely.

Send any VirusTotal API v2 response to the extension via the right-click context menu. It parses the JSON body, extracts all relevant targets, and surfaces them in a dedicated **VT Scope** tab. From there you can add them to Burp's Target Scope and/or inject them into the Site Map with a single click.

---

## Features

- **Manual trigger only**  nothing runs automatically. You control exactly which responses get processed via right-click → *Send to VT Scope Extractor*
- **Response-only parsing**  data is extracted exclusively from the VT API response body, not from request parameters
- **Extracts:**
  - Subdomains (`subdomains[]`)
  - Domain siblings (`domain_siblings[]`)
  - Detected URLs and their hostnames (`detected_urls[]`)
  - Undetected URLs and their hostnames (`undetected_urls[]`)
  - Resolved IP addresses (`resolutions[].ip_address`)
  - Hostnames from IP report resolutions (`resolutions[].hostname`)
- **Add to Scope**  adds extracted hosts and URLs to Burp's Target Scope (both HTTP and HTTPS)
- **Send to Site Map**  injects extracted values as synthetic request/response entries directly into Burp's Target Site Map, highlighted in yellow, ready for active scanning or manual testing
- **Random User-Agent rotation**  each Site Map entry uses a randomly selected real browser User-Agent string from a pool of 10, covering Chrome, Firefox, Edge, Safari, Opera, and mobile browsers
- **Dedicated VT Scope tab**  results shown in a sortable table with Type, Value, and source URL columns
- **Supports all three VT API v2 report endpoints:**
  - `/vtapi/v2/domain/report`
  - `/vtapi/v2/url/report`
  - `/vtapi/v2/ip-address/report`

---

## Requirements

| Requirement | Details |
|---|---|
| Burp Suite | Community or Professional, any recent version |
| Jython | Standalone JAR, version 2.7.x |

Download Jython standalone: https://www.jython.org/download

---

## Installation

1. Download `VTScopeExtractor.py` from this repository

2. Open Burp Suite and go to:
   `Extender` -> `Options` -> `Python Environment`
   Set the path to your Jython standalone `.jar` file

3. Go to:
   `Extender` -> `Extensions` -> `Add`
   - Extension Type: `Python`
   - Extension File: select `VTScopeExtractor.py`
   - Click `Next`

4. You should see `VT Scope Extractor loaded successfully.` in the Output tab and a new **VT Scope** tab appear in Burp's top navigation

---

## Usage

### Step 1  Capture a VirusTotal API response
Browse to a VirusTotal domain/URL/IP report through Burp's proxy, or make the API call manually in Repeater. For example:

```
GET /vtapi/v2/domain/report?apikey=<YOUR_KEY>&domain=example.com HTTP/1.1
Host: www.virustotal.com
```

### Step 2  Send to the extension
In Proxy History, Repeater, or anywhere else in Burp, right-click the request/response and choose:

```
Extensions -> Send to VT Scope Extractor
```

### Step 3  Review extracted results
Switch to the **VT Scope** tab. The table will populate with all extracted values grouped by type:

| Type | Example Value |
|---|---|
| Domain/Sub | `microsites.example.com` |
| Domain/Sub | `www.example.com` |
| URL | `https://microsites.example.com/` |
| IP | `142.195.132.246` |

### Step 4  Push to Burp
Select one or more rows in the table (Ctrl+click or Shift+click for multiple), then click:

| Button | Action |
|---|---|
| `Selected -> Scope` | Adds selected values to Burp Target Scope |
| `Selected -> Site Map` | Injects selected values into Burp Site Map |
| `Selected -> Scope + Site Map` | Does both at once |
| `Clear` | Clears the results table |

---

## Site Map Injection

Each value sent to the Site Map is injected as a synthetic HTTP entry with:
- A realistic `GET /` request to the extracted host
- A randomly rotated User-Agent from a pool of real browser strings
- A `200 OK` placeholder response
- Yellow highlight for easy identification
- Comment tag: `VT Scope Extractor`

This makes the hosts immediately visible in `Target -> Site Map` and available for Burp Scanner, active testing, or crawling.

### User-Agent Pool

The extension rotates through the following browser User-Agents:

- Chrome 124 on Windows
- Edge 123 on Windows
- Firefox 125 on Windows
- Safari 17.4 on macOS
- Chrome 124 on macOS
- Chrome 124 on Linux
- Firefox 125 on Linux
- Safari Mobile on iPhone (iOS 17)
- Chrome Mobile on Android (Pixel 8)
- Opera 109 on Windows

---

## Supported VT Response Fields

| JSON Field | Extracted As |
|---|---|
| `subdomains[]` | Domain/Sub |
| `domain_siblings[]` | Domain/Sub |
| `detected_urls[].url` | URL + hostname as Domain/Sub |
| `undetected_urls[][0]` | URL + hostname as Domain/Sub |
| `resolutions[].ip_address` | IP |
| `resolutions[].hostname` | Domain/Sub |

---

## Disclaimer

This tool is intended for authorised security testing and reconnaissance only. Always ensure you have explicit permission before testing any target. The author is not responsible for any misuse of this tool.

---

## License

MIT License  see [LICENSE](LICENSE) for details.
