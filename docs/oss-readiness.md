# Tailmesh OSS-readiness ledger

This document records engineering findings and publication blockers for the Tailmesh fork. It is not legal advice and does not resolve trademark, patent, or hosted-service rights questions.

## 1. Current publication posture

The source is derived from BSD-3-Clause Tailscale repositories, but the repository is **not yet ready for a one-click public release**.

Current high-priority release gates are:

1. complete a full-history secret scan for both repositories;
2. make the patched core dependency publicly reproducible together with this Android tree;
3. generate and review exact dependency-license notices from the resolved Go and Gradle release graphs;
4. migrate the installed Android application ID away from `com.tailscale.*` and validate ADB/emulator/device behavior afterward;
5. replace/review the remaining inherited launcher, TV, and store promotional artwork;
6. obtain owner/legal sign-off on Tailscale trademark/no-endorsement boundaries, the Tailscale `PATENTS` scope for third-party modifications, and use of Tailscale-hosted infrastructure;
7. decide the diagnostic/log-upload policy for an independently distributed client;
8. resolve the remaining Mullvad trademark/service-presentation question before binary distribution.

## 2. License inheritance

The root `LICENSE` remains the inherited BSD-3-Clause license. Source redistributions must retain the required copyright/license/disclaimer, and binary redistribution must reproduce the required notice material in accompanying documentation/materials.

The root `PATENTS` file is also inherited. It defines "this implementation" as works distributed by Tailscale Inc., grants rights for patent claims necessarily infringed by that implementation, and explicitly excludes claims infringed only as a consequence of further modification. Tailmesh does not reinterpret that text as a new patent grant. Its scope for this modified fork remains a legal-review item.

Inherited source files retain their existing Tailscale copyright/SPDX notices. The project owner should adopt a consistent policy for wholly fork-authored files rather than automatically claiming Tailscale authorship for new work.

## 3. Public identity: current versus planned

The public-facing product name is now **Tailmesh** in the debug/release branding overlays, README, store text, About copy, and project-support flow. The app explicitly states that it is independent and not affiliated with or endorsed by Tailscale Inc.

The installed Android application ID, however, is **still**:

```text
com.tailscale.ipn.multiproxy
```

The intended OSS migration target is an independent ID such as:

```text
io.github.franticplant.tailmesh
```

That migration has intentionally not been folded into the display-branding commit because it affects Android app identity, app-private state, VPN authorization, ADB scripts, and emulator/integration tests. It should be changed and tested as one coherent unit.

The internal Kotlin namespace may remain `com.tailscale.ipn` initially. Package declarations, source directories, the Android resource namespace, `R`, and `BuildConfig` references are tightly coupled; moving all of them is a separate optional refactor.

Factual references such as "Tailscale control server", "Tailscale DNS", `tailscale.com`, `tsnet.Server`, Tailnet terminology, and statements explaining that Tailmesh is derived from Tailscale are retained where technically accurate.

## 4. Branding work completed in this pass

Completed engineering cleanup includes:

- Tailmesh debug/release app name and About/intro copy;
- explicit independent-project/no-endorsement disclosure;
- README rewritten so it no longer presents the fork as the official Tailscale Android client;
- project bug-report link routed to `franticplant/tailmesh-android/issues` rather than Tailscale Support;
- shared manifest app label changed from literal `Tailscale` to `@string/app_name`;
- notification and Quick Settings icons replaced with an independent mesh motif;
- the in-app T-shaped dot mark/animation replaced with a non-T-shaped Tailmesh mesh pattern;
- the inherited `mullvad_logo.png` asset removed from the runtime UI; descriptive Mullvad service text remains;
- store text rewritten as Tailmesh rather than official Tailscale copy;
- an accidentally committed Vim swap file removed.

These changes reduce product-identity confusion but do not themselves settle trademark law or service authorization.

## 5. Branding surfaces still requiring review

Before binary/store distribution, review or replace:

- launcher raster fallback assets under `android/src/main/res/mipmap-*`;
- `android/src/main/ic_launcher-playstore.png`;
- Android TV banner `android/src/main/res/drawable-xhdpi/tv_banner.png`;
- F-Droid/store feature graphics and screenshots under `metadata/en-US/images/`;
- any remaining user-visible upstream product copy discovered in the final APK/AAB resource dump;
- Mullvad-specific exit-node presentation even though the logo asset itself is no longer redistributed.

Where replacement artwork is not ready, omitting inherited promotional artwork from a future release package is safer than presenting official upstream artwork as Tailmesh artwork.

## 6. Mullvad inheritance

The upstream client contains Mullvad-specific exit-node UI. This fork has removed the inherited Mullvad logo asset from the runtime screen, but descriptive text and functionality remain.

Do not assume that Tailscale's commercial/trademark permissions, if any, transfer to an independent fork. Before public binaries, either obtain confirmation that this presentation is acceptable or further neutralize/remove brand presentation while preserving only functionality that is legitimately usable.

This remains an owner/legal question.

## 7. Hosted Tailscale service boundary

The inherited client defaults to Tailscale-operated infrastructure, including the production control/login plane and DERP ecosystem. Other inherited flows also point to Tailscale documentation, account management, support, privacy policy, and terms.

Code redistribution under BSD-3-Clause and use of Tailscale's hosted service are separate questions. Before broad redistribution, decide and validate the product position, for example:

- users bring their own Tailscale account and use Tailscale's hosted service under Tailscale's applicable terms;
- Tailmesh defaults to an independently operated/self-hosted compatible control plane; or
- hosted-service behavior is explicitly gated/documented another way.

Do not treat the BSD code license as hosted-service authorization.

## 8. Diagnostic/log upload

The inherited Go backend contains remote log-upload support using Tailscale's log infrastructure, and Android currently defaults the client-logging preference to enabled unless changed by the user; managed devices force it on.

For an independently branded binary, that deserves explicit product/privacy/ToS review. Before public binary distribution, decide whether Tailmesh should default Tailscale remote logging off, remove/replace it, or retain it only after explicit service/privacy confirmation and disclosure.

This policy has **not** been silently changed during mechanical branding cleanup.

## 9. Dependency-license audit

The reviewed Go inventory contains permissive licenses including BSD-2-Clause, BSD-3-Clause, MIT, ISC, and Apache-2.0. `gvisor.dev/gvisor` is Apache-2.0 and therefore carries its own redistribution, notice, trademark, and patent provisions. The Android/Gradle graph includes similar permissive dependencies plus test dependencies such as JUnit 4 under Eclipse Public License 1.0.

No GPL/AGPL/LGPL blocker was established by the initial generated inventory, but that is not a substitute for resolving the exact release graph.

Before release, generate licenses for the exact Go packages linked into `libgojni`/the AAR and resolve Gradle `releaseRuntimeClasspath`. Verify exact versions/licenses, Apache-2.0 NOTICE and modification obligations, any weak-copyleft terms for artifacts actually shipped, unknown/unclassified licenses, and binary notice requirements.

`.github/licenses.tmpl` is inherited upstream automation and still references Tailscale's generated license ecosystem. It should not be treated as Tailmesh's final binary notice mechanism.

## 10. Patched core publication

`go.mod` intentionally contains:

```go
replace tailscale.com => ../tailscale
```

For this branch, `docs/patches/build-and-maintenance.md` documents the required sibling as `franticplant/tailscale:tailmesh-android-base`, pinned to the Android-compatible core generation and matching Tailscale Go toolchain.

Publishing only the Android repository while that sibling remains private would publish a source tree that is not reproducibly buildable as documented. Before making this repository public, publish the required core fork/branch or replace the sibling arrangement with another public, pinned, reproducible mechanism.

Do not substitute `franticplant/tailscale:main`; it is a different core/toolchain generation.

## 11. Secrets and history

A current-tree scan is insufficient. Before changing repository visibility, scan the **complete Git history of both repositories** for at least Tailscale auth/API/OAuth tokens, GitHub tokens, private control/server URLs, private hostnames/IPs, unintended email addresses, test credentials, JKS/keystore/private keys, `local.properties`, `google-services.json`, and logs/crash dumps.

The current `.gitignore` excludes `tailscale.jks`, local properties, APK/AAB outputs, and native build artifacts, but ignored files can still have existed in history.

Any real credential found in history must be treated as exposed and rotated/revoked; deleting only the current file is insufficient. Known fake/example auth-key strings should be classified as examples rather than blindly treated as live secrets.

## 12. Android application-ID migration implications

Changing from `com.tailscale.ipn.multiproxy` to `io.github.franticplant.tailmesh` (or another independent ID) means Android treats the result as a new application.

Consequences include separate app-private SQLite/encrypted preferences/state-store data, new VPN authorization, new ADB package targets, emulator/test updates, and a distinct future Play Store identity. Existing development installs will not update in place.

For a pre-release fork, this separation is desirable, but it must be executed with the test/tooling changes rather than as a display-only rename.

## 13. Support/account links

Tailmesh software bugs now route to the Tailmesh repository issue tracker rather than Tailscale Support.

Operations that actually act on Tailscale-hosted accounts—such as hosted-service account/tailnet deletion—may correctly remain Tailscale links when the profile uses that service. The UI now identifies those as Tailscale Support/service-specific flows rather than "our support".

## 14. Pre-publication validation

After the remaining OSS changes, run license/header checks, Go unit/race tests for `libtailscale/multiproxy`, patched-core DNS tests, a fresh Gomobile/AAR rebuild, Gradle clean unit tests and debug/release builds, emulator integration, physical-device launch/two-Tailnet smoke tests, ADB package-name verification, and a final APK/AAB resource inspection for inherited marks and notices.

## 15. Open questions for owner/legal counsel

1. Does the inherited Tailscale `PATENTS` grant provide the desired patent coverage for this modified third-party fork, and where does its "further modification" exclusion leave Tailmesh-specific code?
2. What trademark/no-endorsement boundaries should Tailmesh follow for descriptive statements such as "derived from the open-source Tailscale client"?
3. May an independently distributed Tailmesh client default to Tailscale's production control/login/DERP/logging infrastructure, and under what terms/disclosures?
4. Does any upstream permission concerning Mullvad marks/service presentation extend to this independent fork?
5. Has explicit permission already been obtained from Tailscale Inc. or Mullvad that changes the analysis?
6. Is "Tailmesh" itself suitable for intended jurisdictions/store/commercial use after an appropriate trademark search?

## 16. Recommended order from here

```text
P0  Full-history secret scan + rotate anything real that is found
P0  Publish/reproducibly pin the patched core
P0  Independent application-ID migration + integration/device validation
P0  Replace/review remaining launcher/TV/store artwork
P0  Hosted-service + patent + trademark legal review
P1  Generate exact release dependency notices
P1  Decide diagnostic/log-upload policy
P1  Resolve remaining Mullvad presentation question
P1  Refresh store screenshots/feature graphics
P2  Optional internal Kotlin namespace/source-directory refactor
P2  Contribution/DCO/security-reporting/release-process docs
```
