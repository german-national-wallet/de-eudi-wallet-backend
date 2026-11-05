# Wallet backend

This repository contains backend components of the German National Wallet:

* **WPB** (Wallet Provider Backend, Wallet Instance Attestations),
* **RWSCA** (Remote Wallet Secure Cryptographic Application, PIN sessions / remote signing / Wallet Trust Evidence),
* **MDVM** (mobile device verification, platform-integrity checks and MDVM tokens),
* **PNS** (Push Notifications Service), and
* status lists (Token Status List allocation and serving).

Each of WPB, RWSCA, MDVM and PNS ships as its own Spring Boot entry point; status lists are served by WPB. A combined
application runs all of them together. The wallet mobile app (the Wallet Instance) is the only client of the
authenticated APIs; the status-list read surface is public and unauthenticated, consumed by the PID Provider.

This repository is one-way, read-only and flows out of an internal repository.

## Build and run

Prerequisites: a JDK 25, Docker with the compose plugin, SoftHSM and Python 3.12+.

1. **Generate the local key material.** The SoftHSM token store and the dev PKI (roots, chains) are not published;
   generate them as [`softhsm/README.md`](softhsm/README.md) describes. The compose stack builds the token store into
   its images and mounts the roots and chains.
2. **Build the jars.**
   ```bash
   ./gradlew bootJar bootJarMdvm bootJarRwsca bootJarWpb bootJarPns
   ```
3. **Start the stack.** [`docker-compose.yml`](docker-compose.yml) runs PostgreSQL, Kafka, a simulated S3 bucket seeded
   with the generated chains, and the applications on SoftHSM. The combined application listens on
   `localhost:8080`:
   ```bash
   docker compose up --build --wait app-combined
   curl -s localhost:8080/actuator/health/readiness
   ```
   The same file also defines the four separated services (`app-mdvm`, `app-rwsca`, `app-wpb`, `app-pns`), each with its
   own database. They publish no host port and are reachable inside the compose network only:
   ```bash
   docker compose up --build --wait app-mdvm app-rwsca app-wpb app-pns
   ```

`./gradlew build` additionally runs the linters. The test suites are not published, so it executes no tests.

## Local stack limitations

- **Push delivery is off.** PNS stores registrations. Consuming the push-notification topic (`PNS_PUSH_ENABLED`) and the
  FCM transport (`PNS_FCM_ENABLED`, plus a service-account key) are two separate switches; the compose stack sets
  neither.
- **The compose stack relaxes the integrity checks.** `docker-compose.yml` starts MDVM with
  `DEPLOYMENT_ENVIRONMENT: ci-test`, so `src/main/resources/application-ci-test.yaml` applies. That profile lets a
  client skip the platform integrity checks (`allow-skip-key-attestation`: a register or renewal call to MDVM with the
  `Skip-Integrity-Checks: all` request header and no valid attestation still produces an MDVM token), accepts
  software-backed Android keys (`allow-software-key-attestation`) and accepts iOS App Attest development-environment
  attestations (`allow-app-attest-dev-environment`). Skipping is per request and opt-in: a call without the header, or
  with `Skip-Integrity-Checks: none`, is verified in full.
- **The wallet app identity is a placeholder.** The same profile sets the Android package name and signing fingerprint
  (`android.integrity.expected-package-names`, `expected-signer-fingerprints`) and the iOS bundle id and Apple team id
  (`ios.integrity.acceptable-bundle-id-list`, `app-id`) to `org.example.wallet` and zeros. Set these properties to your
  app's values to verify its attestations.
- **The attestation data lists are empty.** `src/main/resources/android/certificate-revocations.json` and both
  `vulnerable_device_classes.json` files are placeholders without entries; the curated lists are not published. Only
  Google's attestation CRL revokes certificates in an Android key attestation chain, and no device is ever classified
  vulnerable.
- **The MDVM admin endpoints are unauthenticated.** `/v1/mdvm/admin/*` (leaked-key management, device class revocation,
  and their pages) authenticate no caller in the backend. Every `POST` and `DELETE`, the device class dry run included,
  needs a JWT in `Authorization`, read unverified: its `preferred_username` claim records who made the call. A gateway
  that logs admins in and forwards their ID token provides both.

## Contributing and issues

Issue tracking is enabled on this mirror. Bug reports and questions about the published source are welcome as
[GitHub issues](https://github.com/german-national-wallet/de-eudi-wallet-backend/issues). Pull requests are still
**not** accepted. For details, see [CONTRIBUTING.md](CONTRIBUTING.md).

Security findings do not belong in issues. Report them through our bug bounty program, see
[SECURITY.md](SECURITY.md).

## Related documentation

- [Architecture Documentation for the German National EUDI Wallet](https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/)

## License

[Apache License 2.0](LICENSE)
