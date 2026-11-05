# Release 16.4

Released to sandbox/production on November 3, 2026

## What's Changed

### Security & Reliability

- CRL revocation checking enabled for all X.509 certificates
- Enabled PIN public key and PIN signature end-to-end encryption

### MDVM

- RASP verify SDK integrated
- Admin pages for device-class revocation and leaked keys

### Production & Operations

- Operations dashboard deployed
- OpenTelemetry switched to 3.0 preview mode

---

# Release 16.2

Released to sandbox/production on October 27, 2026

## What's Changed

### WIA

- WIA status entries are no longer reused

### Security & Reliability

- PKI trust anchors are read at startup instead of on first use, so a bad anchor fails the boot
- Certificate chains are cut below the pinned trust anchor
- revokeDeviceClasses handles database read failures
- Firebase THIRD_PARTY_AUTH_ERROR gets its own retry strategy

### Production & Operations

- Status list expiration time changed
- Records author of MDVM admin operations
- Base images refreshed

---

# Release 15.5

Released to sandbox/production on October 22, 2026

## What's Changed

### Security & Reliability

- Key usage attribute now checked on leaf certificates
- Challenges rejected when the signature part isn’t canonical base64url
- PKCS#11 attributes of scanned HSM keys are checked
- Development upload signing key removed
- WTE lifetime cut to 10 min to match the architecture docs

### MDVM

- Leaked keys list moved from config into the DB, with a new API to manage it
- MDVM token lifetime cut to 60 min
- Expired MDVM token now returns its own error code; shared error handling extracted

### Production & Operations

- Wallet revocation now consumes the new Kafka topic keyed by mdvm_wi_id
- wi_handle column removed
- Logging: json-logging replaced by Spring Boot structured logging
- Helm: released charts pin image digests

---

# Release 15.2

Released to sandbox on September 14, 2026

## What's Changed

### Accounts Lifecycle

- Made mdvm_wi_id mandatory for MDVM tokens.
- Improved WPB/RWSCA account correlation.
- Prevented renewal and deletion of revoked accounts.

### MDVM

- Strengthened Android device security and plausibility checks.
- Added support for additional Android key revocation lists.
- Enforced key attestation and removed Play Integrity verification.
- Improved iOS assertion monitoring.
- Added device-class vulnerabilities verification against the configured database.

### Performance

- Improved status-list performance.
- Replaced the IAIK PKCS#11 wrapper with a native FFM binding.
- Improved HSM concurrency, session recovery, and key operations.

### Monitoring & Configuraton

- Added better HSM tracing and safer key-lineage handling.
- Added PNS health checks and improved PNS startup.
- Moved Kafka topic configuration to Helm.
- Added production profile and improved metrics, version reporting, and tracing.

### OSS & Deployment

- Improved the OSS publishing and synchronization pipeline.
- Replaced the AWS SDK with a custom S3 client
- Updated runtime support to Java 25 and Debian 13.
- Improved Helm configuration for HA synchronization.
- Removed development keys/PKI and other obsolete components.

---

# Release 13.5

Released to sandbox on August 12, 2026

## What's Changed

### Device attestation & app integrity

* iOS: security and plausibility checks for device attestation
* iOS: fix verification of the assertion counter
* Android: verify the second HTTP signature on MDVM renewal
* Allow skipping Play Integrity on Sandbox

### Tokens & attestations

* MDVM token carries the MDVM account ID in a new `mdvm_wi_id` claim
* New claims added to the WIA; presence is verified, values are not consumed yet

### Error handling (API-visible)

* `UNKNOWN_ACCOUNT_ID` replaced by `ACCOUNT_NOT_FOUND`
* New `HSM_UNAVAILABLE` (503) error on MDVM and WPB endpoints
* Internal error codes exposed in telemetry, aligned with the architecture documentation

### New service

* Notification service: database, Helm chart, Docker image, API spec, plus register and delete endpoints. Message wiring
  and push sending follow later.

### Reliability & observability

* Health indicator no longer fails on connection pool saturation
* Metrics for primary key expiration time
* Enforce unique accounts
* Pin the BouncyCastle provider on Nimbus JOSE verifiers/decrypters

---

# Release 13.2

Released to sandbox on July 08, 2026

## What's Changed

* Loosen mobile version checks:
    - Allow dev mobile clients for sandbox backend environment
    - Allow software-backed key attestation for dev/test environments
* Fix HSM related operations
    - Use coroutines to wrap keys in parallel
    - Avoid HSM session borrow leak
* Extend traces with detailed diagnostics for MDVM failures
