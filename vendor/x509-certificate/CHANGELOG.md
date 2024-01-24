# `x509-certificate` History

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

## 0.21.0

Released on 2023-07-24.

* `GeneralizedTime` implements `From<chrono::DateTime<chrono::Utc>>` (#13).

## 0.20.0

Released on 2023-06-03.

* pem upgraded 1.1 -> 2.0.
* ``SignatureAlgorithm`` gained a ``NoSignature`` variant to express a
  a digest without a signature. (#11)
* ``chrono`` compiled without default features (#12).

## 0.19.0

Released on 2023-03-19.

* `Time` now has a `take_opt_from()`.
* `rfc5280::Version` now has a `take_opt_from()`.
* `rfc5280::CertificateList` now has a `take_opt_from()`.
* `rfc5280::TbsCertList` now implements `take_from()`.
* der upgraded 0.6 -> 0.7.
* spki upgrades 0.6 -> 0.7.
* bytes upgraded 1.3 -> 1.4.
* Minimum Rust version 1.61 -> 1.65.

## 0.18.0

Released on 2023-01-21.

* signature upgraded 1.6 -> 2.0.

## 0.17.0

Released on 2022-12-30.

* pem upgraded 1.0 -> 1.1.
* signature upgraded 1.3 -> 1.6.

## 0.16.0

Released on 2022-12-19.

* Canonical home of project moved to https://github.com/indygreg/cryptography-rs.
* chrono crate upgraded from 0.4.22 to 0.4.23.
* Cargo.toml now defines patch versions of all dependencies.

## 0.15.0

(Released 2022-09-17)

* der crate upgraded from 0.5 to 0.6.
* spki crate upgraded from 0.5 to 0.6.

## 0.14.0

(Released 2022-08-07)

* bcder crate upgraded from 0.6.1 to 0.7.0. This entailed a lot of
  changes, mainly to error handling.

## 0.13.0

* `X509Certificate` now implements the `spki::EncodePublicKey` trait.
  This change marks the beginning of a shift/intent to converge this
  crate onto the interfaces defined by crates under the
  [RustCrypto](https://github.com/RustCrypto) umbrella for better
  interop with the rest of the Rust ecosystem.
* `KeyAlgorithm` now implements conversion from/to `spki::ObjectIdentifier`.
* `InMemorySigningKeyPair` now implements `signature::Signer`. This
  means there are now 2 implementations of `sign()` on this type. So
  if both traits are in scope you will need to disambiguate the call.
* The `Sign::sign()` trait method is now marked as deprecated. Please
  switch to the `signature::Signer` trait.

## 0.12.0

* Defined a new `Sign` trait to indicate support for cryptographic
  signing. `InMemorySigningKeyPair` implements this trait and callers
  may need to `use x509_certificate::Sign` to pull the trait into
  scope.
* Some functions for resolving algorithm identifiers now return `Result`.
* Defined RFC 3447 ASN.1 types for representing RSA private keys.
* `InMemorySigningKeyPair` now holds the the raw private key data.
  This enables the content to be retrieved later.
* Added certificate signing request ASN.1 types to the new `rfc2986` module.
* `X509CertificateBuilder` has a new
  `create_certificate_signing_request()` method to create a
  certificate signing request (CSR).

## 0.11.0

* Add some APIs on `Name` to retrieve additional well-known fields.
* Add `Name::user_friendly_str()` for obtaining a user-friendly string
  from a series of attributes.

## 0.10.0

* `CapturedX509Certificate` has gained a
  `verify_signed_data_with_algorithm()` method that uses an explicit
  `ring::signature::VerificationAlgorithm` for verification. The new
  method allows verifying when using an alternative verification
  algorithm. `verify_signed_data()` now internally calls into the new
  function.

## 0.9.0

* Store `version` field of `TbsCertificate` as `Option<Version>`
  instead of `Version`. In 0.8.0 we interpreted a missing optional
  field as version 1. This was semantically correct. However, when we
  encoded the parsed data structure we would invent a new `version`
  field where it didn't exist before. This mismatch is relevant for
  operations like resolving the certificate fingerprint, as the extra
  field would produce a different fingerprint result. Serializing now
  omits the `version` field when it wasn't originally defined. (#525)

## 0.8.0

* Properly parse `TbsCertificate` that is missing a `version` field.
  Before, we\'d get a `Malformed` error if this optional field was
  missing. Now, we correctly interpret a missing field as version 1.
  (#521)

## 0.7.0

* Refactor `GeneralizedTime` parsing to allow fractional seconds and
  timezones. Previously, only limited forms of `GeneralizedTime` were
  parsed. (#482)

## 0.6.0

* Support parsing `RSAPublicKey` from RFC 8017.

## 0.5.0 and Earlier

* No changelog kept.
