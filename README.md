# NextGuard Security Scanner — Joomla

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)
![Joomla](https://img.shields.io/badge/Joomla-4%20%26%205-5091cd)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4)
![Version](https://img.shields.io/badge/version-1.1.0-success)

Official Joomla system plugin for [NextGuard](https://nextguardhq.com). It syncs
your installed Joomla extensions to your NextGuard project so you can monitor your
Joomla stack for known CVEs from a single dashboard.

## Features

- Syncs installed extensions (name + version) on cron or admin action
- Device authorization flow — connect without copy-pasting tokens
- Runs as a lightweight `system` plugin; the API key is stored in the plugin params

## Requirements

- Joomla 4 or 5
- PHP 7.4 or newer
- A NextGuard account on the **Starter** plan or above (CMS plugin sync is included from Starter)

## Installation

1. Download the latest `nextguard-joomla.zip` from the [Releases](../../releases) page
   (or zip `nextguard.xml` + `nextguard.php` together).
2. In Joomla admin go to **System → Install → Extensions → Upload Package File** and
   upload the zip.
3. Enable it under **System → Manage → Plugins** — search for **NextGuard**.
4. Open the plugin and enter your **API Key** (and authorize via the Device Auth flow);
   the **Project ID** is filled automatically after authorization.

## Configuration

| Setting    | Where to find it                               |
|------------|------------------------------------------------|
| API Key    | NextGuard → **Account → API Keys**             |
| Project ID | Auto-filled after Device Authorization         |

## How it works

The plugin collects installed extensions and sends a signed `POST` to
`https://nextguardhq.com/api/v1/cms/sync` with your API key in the `X-API-Key`
header, on Joomla cron or a manual admin trigger.

## Troubleshooting

**Sync not running** — Ensure Joomla scheduled tasks / cron are configured, and that
the server can make outbound HTTPS requests to `nextguardhq.com`.

**Verify it worked** — In your NextGuard project, look for a file named
`cms-manifest-joomla.json`.

## License

Released under the [GNU General Public License v2.0](LICENSE) or later, consistent
with the Joomla ecosystem.
