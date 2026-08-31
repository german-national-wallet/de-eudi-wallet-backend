# Security policy

## Scope and limitations

This repository is a **sanitized, read-only mirror** of the private development repository for the
backend of the National German EU Digital Identity Wallet. Before assessing it, please note:

- Configuration is not published: the classes that declare the settings are published, so the shape
  of what the code accepts and its compiled-in defaults are readable — the values behind them are
  not. Findings that turn on configuration this mirror does not contain are out of scope.
- The mirror is published on a regular basis. **Only the latest published state is in scope** for
  security research; earlier commits are historical snapshots.
- Issues already known and tracked internally may be dismissed as duplicates.
  *A list of publicly acknowledged known issues will appear here.*

## Reporting a vulnerability

*The bug-bounty program for this project is being set up; its link, scope and reward details will
appear here.*

Findings must be reported through that program (not via GitHub issues — issue tracking is disabled
on this mirror).

**Good-faith security research within the program's scope will not result in legal action.**

## Contribution model

This mirror accepts **no pull requests**, and **issue tracking is currently disabled**. The private
repository is the source of truth; fixes appear here with the next published sync.

## Dependencies

The backend depends on open source libraries. Vulnerabilities in upstream
dependencies should be reported to the respective upstream project; their use here is in scope only
where this codebase's usage is itself the flaw.
