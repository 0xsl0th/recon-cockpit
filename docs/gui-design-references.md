# GUI design references — 6 October 2026

Enrique selected his **Swiss Industrial** light and dark mockups as the starting
point for the later GUI. Preserve both themes and review the originals when GUI
work begins; this note records design direction, not implemented functionality.

Original local files:

- `/home/sloth/Downloads/Swiss_Industrial.png`
- `/home/sloth/Downloads/Swiss_Industrial_dark.png`

Private preserved copies and a source/hash manifest are at
`/home/sloth/Code/recon-cockpit/.secure-agent/gui-design-references-20261006/`.
The PNG files are kept locally, outside Git. The tracked design reference is this
document; the user did not request publishing the image files.

## Layout to carry forward

- Compact left navigation: overview, scope, timeline, evidence, findings, tools,
  model usage, audit and reports.
- A visible engagement selector and session state, with a dense central timeline.
- A prominent action review panel showing the exact proposed action, target,
  effects, relevant bounds and the operator's approve/deny choices.
- Recent evidence and findings close to their execution context; a persistent
  audit/status strip. Use restrained orange accents, clear typography and both
  light and dark themes.

Use the existing authority and evidence APIs for GUI actions. A GUI must never
run commands directly, fabricate approvals, restore expired authority or treat
tool output as instructions. First implement useful scope/session/evidence views
and cancellation through the same secure execution path as the CLI.

Mockup example organizations, external targets, online agents, model names,
dollar amounts, confidence scores and signing/verification labels are illustrative.
The first GUI must show actual offline state and zero provider calls where that
is the observed state. Do not imply authenticated findings, signatures, paid
models or professional engagement readiness without supporting implementation
and evidence. Credentials and live models remain deferred.
