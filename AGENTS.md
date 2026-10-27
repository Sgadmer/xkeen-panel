# Development contract

- Preserve the Dearonski upstream history and attribution. This fork publishes
  panel updates only from `Sgadmer/xkeen-panel`.
- Commits materially assisted by Codex include
  `Co-authored-by: Codex <codex@openai.com>` without replacing the human author.
- Never commit runtime data, subscriptions, HWID values, RCI tokens, credentials,
  router backups, logs or screenshots containing real user/device/server data.
  Use `example.com`, documentation IP ranges and synthetic fixtures.
- Preserve provider profiles and manual selection during transactions. Reject
  unsupported combinations clearly; keep the old configuration on failure.
- Installation must audit first, distinguish clean setup from migration and
  preserve recoverability. A novice should not need to invent shell commands.
- Validate backend with `go test ./...`, frontend with `npm run build`, installer
  with its fixture tests, and public source with `scripts/check-public-source.py`.
- Keep README claims aligned with tested behavior and release screenshots.
