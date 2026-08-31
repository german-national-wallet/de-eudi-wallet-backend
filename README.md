# Wallet backend

Backend components of the National German EU Digital Identity Wallet: **WPB** (Wallet Provider
Backend, Wallet Instance Attestations), **RWSCA** (Remote Wallet Secure Cryptographic Application,
PIN sessions / remote signing / Wallet Trust Evidence), **MDVM** (mobile device verification,
platform-integrity checks and MDVM tokens), **PNS** (Push Notifications Service) and status lists
(Token Status List allocation and serving). Each of WPB, RWSCA, MDVM and PNS ships as its own
Spring Boot entry point; status lists are served by WPB. A combined application runs all of them
together. The wallet mobile app (the Wallet Instance) is the only client of the authenticated APIs;
the status-list read surface is public and unauthenticated, consumed by the PID Provider.

## What this repository is

A **sanitized, read-only source mirror** of the private development repository, published so the
source can be read and audited rather than run: **it will not compile as-is.** Sanitization drops
files whole — so expect published code to reference constants and packages this mirror does not
contain — and **strips every comment** from the sources that remain.

## Contributing and issues

**On hold.** This mirror accepts no pull requests, and issue tracking is currently disabled to
avoid low-quality automated reports. Security findings are welcome through the channel described
in [SECURITY.md](SECURITY.md).

## Related documentation

- [Architecture reference documentation](https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/)

## License

[Apache License 2.0](LICENSE)
