# Claude repository guidance

Follow [`AGENTS.md`](AGENTS.md) for always-on repository safety and select the relevant portable guide in [`.claude/skills/`](.claude/skills/). Skills are advisory instructions, not runtime enforcement. Claude discovers these skills from `.claude/skills/<name>/SKILL.md` in a newly mounted session; remount/reopen the repository session if they do not appear.
