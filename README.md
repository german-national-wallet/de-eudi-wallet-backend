# Wallet backend

This repository contains backend components of the German National Wallet: 
* **WPB** (Wallet Provider Backend, Wallet Instance Attestations),
* **RWSCA** (Remote Wallet Secure Cryptographic Application, PIN sessions / remote signing / Wallet Trust Evidence),
* **MDVM** (mobile device verification, platform-integrity checks and MDVM tokens),
* **PNS** (Push Notifications Service), and
* status lists (Token Status List allocation and serving).

Each of WPB, RWSCA, MDVM and PNS ships as its own Spring Boot entry point; status lists are served by WPB.
A combined application runs all of them together.
The wallet mobile app (the Wallet Instance) is the only client of the authenticated APIs;
the status-list read surface is public and unauthenticated, consumed by the PID Provider.

This repository is one-way, read-only and flows out of an internal repository.

## Scope

**Configuration file is coming** Currently, the shape of what the code accepts and its compiled-in defaults are readable from the classes that declare the settings. 

## Contributing and issues

Issue tracking and pull requests are **not** enabled on this mirror right now. Issue tracking is planned to be enabled in September.

Any findings, especially security related ones are very welcome. Please find details on the bug bounty in [SECURITY.md](SECURITY.md).

## Related documentation

- [Architecture Documentation for the German National EUDI Wallet](https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/)

## License

[Apache License 2.0](LICENSE)
