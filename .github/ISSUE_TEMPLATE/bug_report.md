---
name: Bug report
about: Something isn't working as documented
title: ''
labels: bug
assignees: ''
---

<!--
  Please do NOT use this form for security vulnerabilities — see SECURITY.md
  and email security@cyfar.ca instead.

  A false positive (clean package flagged) or false negative (malicious package
  missed) is welcome here. If you can, name the package + version and the rule_id.
-->

**What happened**
A clear description of the bug.

**What you expected**
What you expected to happen instead.

**Steps to reproduce**
1. ...
2. ...

**Environment**
- pkgward version / commit:
- How you're running it (standalone compose / BYO Postgres / from source):
- OS + Docker version:
- Ecosystem(s) involved (PyPI / crates.io / Go / npm):

**Logs / output**
Relevant `docker logs pkgward` output or a finding's `rule_id` and evidence.
Please redact anything sensitive.
