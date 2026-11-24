# LineageOS images for Google Pixel

Thin adapter around the official LineageOS build
(https://github.com/LineageOS/lineage_wiki, `pages/build/<device>.md` and
`pages/signing_builds.md`). Upstream owns the source tree, Pixel vendor
extraction (the device tree's `extract-files.py`), compilation and release
signing (`sign_target_files_apks`, `ota_from_target_files`,
`img_from_target_files`). This repository pins a manifest commit, runs those
tools as an unprivileged account and packages the signed result. It adds no apps
and changes no branding, so its output is an unofficial build of the official
sources. It is not affiliated with the LineageOS project.

The platform writes `config/lineageos.json`:

```json
{"schema_version": 1, "device": "frankel", "model": "Pixel 10", "branch": "lineage-24.0",
 "manifest_url": "https://github.com/LineageOS/android.git",
 "manifest_commit": "<commit on lineage-24.0>"}
```

`./build.sh prepare` refuses if less than 300 GiB is free. It runs
`repo init -b <manifest_commit>`, checks that the commit is on the branch,
syncs, runs `breakfast <device> user` and extracts the vendor files from the
Google factory image that LineageOS pins (URL and SHA-256) in
`vendor/lineage/vars/<device>`. For the compile only it takes the host-wide
`/var/cache/goldengoose/.android-compile.lock` (shared with the GrapheneOS
adapter, so compiles take turns), refusing if another compile holds it or free
space has dropped below 300 GiB, and builds `target-files-package` and
`otatools-package` into `LINEAGEOS_CACHE_DIR/releases/<manifest_commit>/`. A
failed compile keeps `out/`, so retrying the same commit is incremental; a new
commit's sync removes it.
LineageOS does not sign its manifests or tags, and its manifest tracks branch
heads, so the commit pins the project list only. The compile therefore also
records `repo manifest -r`, the exact project revisions, which every bundle
carries as `source-manifest.xml`.

`./build.sh` then signs for one owner and never compiles: it refuses when the
pinned commit is not compiled for the device. `LINEAGEOS_SECRETS_DIR` must be
outside this workspace and the cache and hold `passphrase` and, after the first
build, `keys/<device>/` with that owner's encrypted keys. A missing key set is
created with upstream `make_key` (the key names `sign_target_files_apks -d`
maps, plus `nfc`, which `-k` maps so the SELinux `mac_permissions.xml` moves with
NfcNciApex) and a 4096-bit AVB key; every private key is encrypted with scrypt
PKCS#8 as GrapheneOS `script/encrypt-keys` does, and decrypted only into tmpfs
while signing. Other APKs and APEXes that the build left on source-tree keys are
signed with the owner's release key, and APEX payloads, vbmeta and every
partition chained to it with the owner's AVB key; the list comes from the target
files' own key metadata. The images are checked against the owner's AVB key,
the OTA against their release key, and the signed `mac_permissions.xml` files
for any signer still on a public source-tree certificate, then written to
`output/lineageos-factory.zip` with the boot images LineageOS's install guide
flashes, the signed OTA package, `INSTALL.txt` and a manifest of SHA-256
digests. Private keys are never packaged.

Like official LineageOS builds, vbmeta does not enforce verified boot (no
`WITH_AVB`), so the bootloader stays unlocked, and recovery also trusts
LineageOS's official OTA key (`PRODUCT_EXTRA_RECOVERY_KEYS`); installing an
official build over this one changes the signing keys and needs a wipe.

Run as root, the adapter installs prerequisites with `install-dependencies.sh`
and runs every upstream step as the `of-lineageos` account through `setpriv`
(`--no-new-privs`, empty capability bounding set, clean environment). The cache
keeps one source tree (`src`) and moves it in place to each newly pinned
commit; compiled output of earlier commits is deleted. LineageOS asks for
400 GB of storage and 64 GB of RAM for lineage-21 and later. Set
`LINEAGEOS_JOBS` to limit compile parallelism.

The build proves compilation and signatures only. Flashing, boot, radios and
updates must be tested on the exact phone.

The adapter is MIT-licensed. LineageOS and AOSP retain their own licences;
sources are available from https://github.com/LineageOS.
