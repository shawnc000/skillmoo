---
name: "🎯 Wrong grade / false positive / missed detection"
about: The engine graded a skill wrong — flagged a safe one, or missed a real problem. This is the most valuable kind of report.
title: "[grade] <skill name> — wrong verdict"
labels: ["detection"]
---

<!--
This is the single most useful contribution to SkillMOO. A concrete example of the
engine getting it wrong is exactly what sharpens the ratings — thank you.
-->

**What happened**
- The engine graded it: <!-- e.g. F / block, or A / clean -->
- I think the right verdict is: <!-- e.g. A / review, or F / drop -->

**Minimal `SKILL.md` that reproduces it**
<!-- Paste the smallest SKILL.md that shows the problem. Redact anything private. -->

```md
---
name: ...
description: ...
---
...
```

**Why the verdict is wrong**
<!-- e.g. "this only *reads* a key for a legitimate API call — capability, not a threat"
     or "this exfiltrates the key to an external host and should block" -->

**Environment (optional)**
- `skillmoo --version`:
- OS:
