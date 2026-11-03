---
title: Privacy
description: "What Reach sends, to whom, and when. In short: nothing, unless you ask for it."
---

Reach collects no data about you. There is no analytics, no telemetry, no crash reporting and no account, and there is no Reach server for anything to be sent to. This page lists every connection the app makes, so you can check that for yourself.

## What Reach connects to on its own

- **Update checks.** On startup and periodically while it runs, Reach downloads a small file describing the latest release from GitHub (`github.com/alexandrosnt/Reach/releases`). GitHub sees the request like any other download: your IP address and the app's version in the request. Nothing about you or your machines is sent.

That is the only connection Reach makes without you asking for it.

## What it connects to because you asked

- **Your servers.** SSH, SFTP, port tunnels, remote desktop and database connections go to the hosts you enter, and nowhere else.
- **Catalogues.** Opening the theme, recipe or plugin catalogue downloads its list from GitHub (`raw.githubusercontent.com`).
- **Cloud sync, if you turn it on.** Your encrypted vault is synced to a Turso database in your own Turso account. Reach talks to Turso's API with the token you provide. The data is encrypted on your device before it leaves.
- **The AI assistant, if you turn it on.** Your questions, and any terminal output or SQL you choose to include, are sent to OpenRouter with your own API key, and from there to the model you picked. Their privacy terms apply to what you send.
- **Session sharing, if you turn it on.** Terminals are shared directly between the two computers over WebRTC, encrypted end to end. To find a route between the two machines, each side asks a public STUN server (Cloudflare's and Google's by default, or ones you configure) for its own public address. The invitation codes are exchanged by you, by copy and paste; no Reach server is involved.
- **The MCP server, if you turn it on.** It listens on this computer only (loopback), for the AI tools you connect to it.

## Where your data is kept

Sessions, passwords, SSH keys, database connections and settings are stored on your device, encrypted in Reach's vault. Query history and a few interface preferences are kept in the app's local storage on the device. If you turn on sync, the encrypted vault is also stored in your own Turso database. Deleting the app's data folder removes everything.

## This website

reachssh.com is a static site hosted on GitHub Pages. GitHub, as the host, receives the usual request information such as IP addresses; see [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

The site asks once whether it may use Google Ads cookies, to measure which ads bring visitors here. Until you accept, Google's script is not loaded at all: nothing is sent to Google and no cookie is set. If you accept, Google receives your visit (the page, your IP address and the cookie it sets) under [Google's privacy policy](https://policies.google.com/privacy); this is used to count ad conversions, not to build a profile on this site. There is no other analytics. Your choice is kept in your browser only.

<button id="ads-consent-change" type="button">Change my cookie choice</button>

None of this concerns the Reach app, which makes no such connections.

## Questions

Open an issue at [github.com/alexandrosnt/Reach](https://github.com/alexandrosnt/Reach/issues), or ask on the [Discord](https://discord.gg/CSbEybvDVV).
