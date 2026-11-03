# Security Policy

## Supported versions

Reach is released often, and fixes go into the next release rather than being
backported. Only the latest release gets security fixes, so please update
before reporting.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Anything older | No        |

## Reporting a vulnerability

Please don't open a public issue for a security problem.

Report it privately through GitHub instead:
[Report a vulnerability](https://github.com/alexandrosnt/Reach/security/advisories/new).
Only the maintainer can see the report.

Please include:

- what the problem is and what an attacker could do with it,
- the Reach version and platform (Windows, macOS, Linux or Android),
- steps to reproduce it, or a proof of concept.

## What happens next

- You'll get a reply within 7 days saying whether the report was received and
  can be reproduced.
- If it's accepted, a fix is worked on privately and shipped in a new release,
  usually within 30 days depending on how serious and how complex it is. You'll
  be kept up to date along the way.
- Once the release is out, the advisory is published, crediting you unless you
  would rather not be named.
- If it's declined, you'll be told why.

## Scope

In scope: the Reach app on every platform, its vault and sync, its SSH, SFTP,
RDP and database connections, the MCP server, plugins as run by Reach, and the
release and update process.

Out of scope: problems in servers or services Reach connects to, and issues
that need an attacker to already control your device or your unlocked vault.
