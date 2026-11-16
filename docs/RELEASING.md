# Releasing GimmeCores

A release is a tag `vX.Y.Z` on `main`. GitHub Actions (`release.yml`) builds the binaries and
the macOS app into a **draft** release, with signed build provenance. The maintainer then
signs the app's update on their own Mac and publishes the draft (`scripts/release-mac.sh`).
Installed apps see nothing until the release is published.

## The update key

Every installed GimmeCores app trusts exactly one update key: its public half is built into the
app (`packaging/release/update-key.pub`). Whoever holds the secret half can make every
installed copy run their code, so:

- It is made once, on the maintainer's Mac, with a password:

  ```sh
  cargo run -p gimmecores-release --bin gmc-release -- keygen --dir ~/.gimmecores-release
  ```

  That writes `gimmecores-update.key` (secret, mode 0600, encrypted with the password; never
  overwritten) and `gimmecores-update.pub`, and prints the line to save as
  `packaging/release/update-key.pub` (commit it on the development branch, merge it with a PR).
- It never goes to GitHub, CI, a cloud drive or anyone else. Keep an **offline backup** of the
  key file and its password (for example on an encrypted USB drive in a drawer): without them,
  installed copies can never be updated again and every user must reinstall by hand.
- If it may have leaked: stop releasing with it, make a new key, release a version built with
  the new public key, and tell users to install that version by hand (the old key would be
  trusted by older copies until they update). Say so in the release notes and SECURITY.md.

A build without `packaging/release/update-key.pub` works but cannot update itself; release
builds (`GMC_RELEASE=1`) refuse to start without it.

## What the app checks before it updates (I12)

Checking contacts GitHub only when the user clicks **Check for updates** (Settings > Updates).
Before anything replaces the app:

1. The app must be installed in `/Applications` or `~/Applications` (not a build folder, a disk
   image or Homebrew's own folder, which `brew upgrade` updates).
2. The manifest comes from `https://github.com/tanuj24/gimmecores/releases/latest/download/latest.json`
   and must offer a **newer** version (no downgrades, no replays of the installed one).
3. The download must be one of this project's release files, over https.
4. The archive must be signed with the built-in key, and the signature's trusted comment must
   name exactly the announced version (`requireSignedVersion`), so a genuine old release cannot
   be relabelled as a new one; a signature without a version is refused.
5. The archive may hold only plain files and folders inside `GimmeCores.app/` (no `..`, links,
   devices or setuid bits), the bundle identifier `dev.gimmecores.desktop`, exactly the
   announced version, and its programs (`crates/gimmecores-bundle`).

After the update the background service restarts if it runs the app's own `gmcd` (tasks
running for other devices stop; the window says so first), and the app reopens.

Limits, stated plainly: whoever holds the key can ship anything; GitHub (or someone in control
of the account) can withhold updates or keep serving an older manifest, which the app cannot
detect; the app is ad-hoc signed, so after an update macOS may ask again to allow incoming
connections and to use the Keychain item.

## Steps

1. Bump `version` in `apps/desktop/Cargo.toml` (the app's only version: `Info.plist` and the
   updater read it) and in the crates if they changed; merge to `main` with a PR.
2. Tag the merge commit and push the tag: `git tag -a vX.Y.Z -m "GimmeCores X.Y.Z" <commit>` (`-s` instead of `-a` signs it, once a signing key is set up), then `git push origin vX.Y.Z`.
   Pushing the tag starts `release.yml` on GitHub's runners (free for public repositories),
   which builds into a draft release with provenance. Without it (no GitHub Actions run, or
   no app in the draft), step 4 builds the app on the maintainer's Mac from the tag instead.
3. Write the release notes as plain text (the app shows them as text, cut to 2000 characters).
4. Run, on the maintainer's Mac, in a clean checkout of `main`:

   ```sh
   scripts/release-mac.sh X.Y.Z --key ~/.gimmecores-release/gimmecores-update.key --notes notes.txt
   ```

   It refuses unless the tag is the same commit here and on GitHub and is on `main`. It takes
   the app from the draft release after checking its provenance
   (`gh attestation verify --signer-workflow …/release.yml --source-ref refs/tags/vX.Y.Z`), or
   builds it here from a clean checkout of the tag when there is none. It checks the app holds
   the committed public key and is not a test build, refuses an archive the app would refuse,
   asks for the key's password, verifies the signature as the app will, writes `latest.json`,
   and uploads after you confirm. It publishes only if you type the version.
5. Commit the updated `Casks/gimmecores.rb` (version and checksum of the new disk image) on the
   development branch and merge it with a PR.

## Windows

`packaging/windows/build-installer.sh` builds `dist/GimmeCores-X.Y.Z-x64-setup.exe` on the
maintainer's Mac (cross-compiled with MinGW and packed with NSIS, in Docker). Upload it, with its
checksum, to the same draft release before publishing:

```sh
packaging/windows/build-installer.sh
(cd dist && shasum -a 256 GimmeCores-X.Y.Z-x64-setup.exe > SHA256SUMS-windows)
gh release upload vX.Y.Z dist/GimmeCores-X.Y.Z-x64-setup.exe dist/SHA256SUMS-windows
```

Before that, `scripts/windows/test-windows.sh`, `scripts/windows/e2e-borrow.sh` and
`scripts/windows/password-approval.sh` pass on the test VMs (docs/design/windows.md). The installer is not signed yet, so SmartScreen asks once,
and Windows copies do not update themselves yet: people install the new version over the old.

## Testing updates

`scripts/test-self-update.sh` (also part of `scripts/ci-local.sh mac`) builds a test app
(`update-test` feature, never in a shipped build) in a temporary folder, serves updates from
127.0.0.1 with a throwaway key, and checks that a correct update installs and that every case
above is refused. It never touches this Mac's GimmeCores or its login item. The swap inside
`/Applications` itself (permissions, the administrator prompt) is exercised only by a real
release.
