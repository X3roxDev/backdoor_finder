# Backdoor Finder

Server-only FiveM resource scanner that reports suspicious code patterns across installed resources.

## Features

- Scans resource manifests and common script files for risky indicators
- Runs automatically on resource start and on a configurable interval
- Supports manual scans from the server console
- Skips oversized and binary assets to keep checks responsive
- Reports new findings to the console and optionally to Discord
- Uses a scoring threshold so noisy low-risk patterns can be ignored

## Quick Start

```cfg
ensure backdoor_finder
```

1. Place `backdoor_finder` in your server `resources` folder.
2. Review `config.lua` and set ignored resources, scan interval, and webhook options.
3. Add `ensure backdoor_finder` to `server.cfg`.
4. Restart the server, or run `refresh` and `ensure backdoor_finder`.

## Configuration

Edit `config.lua` to change scan intervals, the minimum score, ignored resources, maximum file size, webhook settings, and scannable extensions.

## Notes

This tool is a defensive scanner, not a full malware analyst. Treat findings as leads to review manually before deleting or blaming a resource.
