#!/usr/bin/env python3
"""Build stock LineageOS from its official sources and sign it with the owner's keys.

Upstream owns the source tree, Pixel vendor extraction (the device tree's
extract-files.py), compilation and the release tools (sign_target_files_apks,
ota_from_target_files, img_from_target_files). This adapter pins a manifest
commit, runs those tools as an unprivileged account, and packages the signed
output with provenance.

The compiled target files depend only on (manifest commit, device), so
`prepare` builds them once into the cache and every build of that pair only signs.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent
MANIFEST_URL = 'https://github.com/LineageOS/android.git'
BRANCH = 'lineage-24.0'
BUILD_USER = os.environ.get('LINEAGEOS_BUILD_USER', 'of-lineageos')
MIN_FREE_BYTES = 300 * 1024**3
KEY_SUBJECT = '/CN=OpenFactory LineageOS build/'
# The names `sign_target_files_apks -d` maps to the key directory (testkey and devkey map to releasekey).
DEFAULT_KEYS = ('releasekey', 'platform', 'shared', 'media', 'networkstack', 'sdk_sandbox', 'bluetooth')
# Source-tree certificates -d leaves alone. --key_mapping (-k) moves *_mac_permissions.xml with
# the APK, so NfcNciApex (com.android.nfcservices, security/nfc) keeps its SELinux domain.
EXTRA_KEYS = ('nfc',)
AVB_ALGORITHM = 'SHA256_RSA4096'
# LineageOS's install guide flashes these from the bootloader, the last one as recovery
# (lineage_wiki _data/devices/frankel.yml: before_recovery_install, recovery_partition_name).
FLASHED_IMAGES = ('boot', 'dtbo', 'vendor_kernel_boot', 'vendor_boot')
RECOVERY_IMAGE = 'vendor_boot'
PRIVATE_KEY_NAME = re.compile(r'(\.pk8|\.pem|\.gpg|id_ed25519)$')
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@+-]*')


def digest(path, algorithm='sha256'):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def read_config(path):
    config = json.loads(Path(path).read_text())
    if (not isinstance(config, dict)
            or set(config) != {'schema_version', 'device', 'model', 'branch', 'manifest_url', 'manifest_commit'}
            or config['schema_version'] != 1
            or not re.fullmatch(r'[a-z][a-z0-9]{2,15}', str(config['device']))
            or config['branch'] != BRANCH
            or config['manifest_url'] != MANIFEST_URL
            or not re.fullmatch(r'[0-9a-f]{40}', str(config['manifest_commit']))
            or not re.fullmatch(r'[A-Za-z0-9 .+-]{1,40}', str(config['model']))):
        raise ValueError('Invalid pinned LineageOS device or manifest commit')
    return config


def secrets_dir(cache):
    value = os.environ.get('LINEAGEOS_SECRETS_DIR', '')
    path = Path(value).resolve() if value else None
    if (path is None or not path.is_dir() or path.is_relative_to(ROOT.resolve())
            or path.is_relative_to(cache.resolve())):
        raise ValueError('LINEAGEOS_SECRETS_DIR must be a directory outside the workspace and cache')
    password = (path / 'passphrase').read_text().rstrip('\n')
    if len(password) < 32 or '\n' in password:
        raise ValueError('The signing passphrase is missing or malformed')
    return path, password


def builder_argv(home):
    """Run upstream tools as the build account with no privileges and a clean environment."""
    environment = {'HOME': str(home), 'USER': BUILD_USER, 'LANG': 'C.UTF-8', 'TERM': 'dumb',
        'TMPDIR': f'{home}/tmp', 'PATH': f'{home}/bin:/usr/local/bin:/usr/bin:/bin'}
    jobs = os.environ.get('LINEAGEOS_JOBS', '')
    if re.fullmatch(r'[1-9][0-9]{0,3}', jobs):
        environment['LINEAGEOS_JOBS'] = jobs
    prefix = []
    if os.geteuid() == 0:
        account = pwd.getpwnam(BUILD_USER)
        prefix = ['setpriv', f'--reuid={account.pw_uid}', f'--regid={account.pw_gid}', '--clear-groups',
            '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all']
    return [*prefix, 'env', '-i', *(f'{key}={value}' for key, value in environment.items())]


def give_to_builder(*paths, only_if_needed=False):
    """chown -R to the build account; with only_if_needed, skip trees it already owns."""
    if os.geteuid() == 0:
        account = pwd.getpwnam(BUILD_USER)
        for path in paths:
            if only_if_needed and Path(path).stat().st_uid == account.pw_uid:
                continue
            subprocess.run(['chown', '-R', f'{account.pw_uid}:{account.pw_gid}', str(path)], check=True)


@contextlib.contextmanager
def locked(path, waiting=None):
    """Hold an exclusive flock on path, refusing a symlink or anything but a regular file there."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'rb') as lock:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f'{path} is not a regular file; refusing to lock it')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if waiting:
                print(waiting, flush=True)
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def compile_lock(cache):
    """One Android compile at a time on this host; the GrapheneOS cache beside this one shares the lock
    (/var/cache/goldengoose/.android-compile.lock)."""
    return locked(cache.parent / '.android-compile.lock', 'Waiting for another Android compile on this host to finish')


def require_free_space(path, out):
    """Count a kept out/ as reclaimable: a retry reuses it and a new commit's sync removes it."""
    free = shutil.disk_usage(path).free
    kept = int(subprocess.check_output(['du', '-s', '--block-size=1', str(out)]).split()[0]) if out.is_dir() else 0
    if free + kept < MIN_FREE_BYTES:
        held = f' plus {kept // 1024**3} GiB in {out} from an earlier compile' if kept else ''
        raise SystemExit(f'Refusing to prepare LineageOS: {free // 1024**3} GiB free in {path}{held}, '
            f'{MIN_FREE_BYTES // 1024**3} GiB needed.')


def signing_args(target_files):
    """Owner-key flags for every APK, APEX and AVB signer the build left on a source-tree test key.

    The LineageOS signing guide lists these by hand; reading them from the
    target files' own key metadata keeps a new APEX from shipping test-signed.
    """
    def entries(text):
        return [dict(re.findall(r'(\w+)="([^"]*)"', line)) for line in text.splitlines() if line.strip()]

    def checked(name):
        if not SAFE_NAME.fullmatch(name):
            raise ValueError(f'Unexpected package name in target files: {name!r}')
        return name

    with zipfile.ZipFile(target_files) as archive:
        misc = dict(line.split('=', 1) for line in archive.read('META/misc_info.txt').decode().splitlines()
            if '=' in line)
        apks = entries(archive.read('META/apkcerts.txt').decode())
        apexes = entries(archive.read('META/apexkeys.txt').decode())
    devkeys = os.path.dirname(misc.get('default_system_dev_certificate', 'build/make/target/product/security/testkey'))
    mapped = {f'{devkeys}/{name}.x509.pem' for name in (*DEFAULT_KEYS, *EXTRA_KEYS, 'testkey', 'devkey')}
    args = [arg for name in EXTRA_KEYS for arg in ('--key_mapping', f'{devkeys}/{name}=keys/{name}')]
    for apk in apks:
        if apk.get('certificate') not in {None, '', 'PRESIGNED', 'EXTERNAL', *mapped}:
            args += ['--extra_apks', f'{checked(apk["name"])}=keys/releasekey']
    for apex in apexes:
        if 'PRESIGNED' not in (apex.get('private_key'), apex.get('container_certificate')):
            name = checked(apex['name'])
            args += ['--extra_apks', f'{name}=keys/releasekey', '--extra_apex_payload_key', f'{name}=keys/avb.pem']
    # vbmeta and every partition chained to it; this option sets any partition's AVB key.
    for partition in sorted(match.group(1) for key in misc if (match := re.fullmatch(r'avb_(\w+)_key_path', key))):
        args += ['--avb_extra_custom_image_key', f'{partition}=keys/avb.pem',
            '--avb_extra_custom_image_algorithm', f'{partition}={AVB_ALGORITHM}']
    return args


@contextlib.contextmanager
def prepare_marker(cache):
    """Lock `.openfactory-preparing` for one prepare; the platform queues Pixel builds meanwhile.

    So none waits out its slot on the cache lock. The kernel drops the lock with
    this process however it ends; the pid is only for operators. The host's
    prepare loop (OpenFactory `scripts/grapheneos-host.py`) holds it across
    every Pixel and sets OPENFACTORY_PREPARE_LOCK_HELD=1; locking it again here
    would wait for that loop forever.
    """
    if os.environ.get('OPENFACTORY_PREPARE_LOCK_HELD') == '1':
        yield
        return
    marker = cache / '.openfactory-preparing'
    with marker.open('w') as held:
        os.fchmod(held.fileno(), 0o644)  # the platform's API account opens it read-only
        fcntl.flock(held, fcntl.LOCK_EX)
        held.write(f'{os.getpid()}\n')
        held.flush()
        try:
            yield
        finally:
            marker.unlink(missing_ok=True)


class Builder:
    def __init__(self, config, cache):
        self.config, self.cache = config, cache
        self.device, self.commit = config['device'], config['manifest_commit']
        self.home = cache / 'home'
        # One tree, moved in place to each pinned manifest commit so a bump
        # fetches only what changed instead of a fresh sync.
        self.tree = cache / 'src'
        self.releases = cache / 'releases'
        self.work = cache / f'sign-{self.device}'
        self.logs = cache / 'logs'
        self.redact = []

    def step(self, name, script, *, cwd=None, stdin='', variables=None):
        """Run one upstream step; the full log stays in the cache, progress goes to stdout."""
        log = self.logs / f'{self.commit[:12]}-{self.device}-{name}.log'
        exports = ''.join(f'export {key}={shlex.quote(str(value))}\n' for key, value in (variables or {}).items())
        argv = [*builder_argv(self.home), 'bash', '-c', 'set -euo pipefail\n' + exports + script]
        print(f'==> {name}', flush=True)
        started = time.monotonic()
        with log.open('ab') as output:
            proc = subprocess.Popen(argv, cwd=cwd or self.tree, stdin=subprocess.PIPE,
                stdout=output, stderr=subprocess.STDOUT)
            proc.stdin.write(stdin.encode())
            proc.stdin.close()
            while True:
                try:
                    code = proc.wait(timeout=60)
                    break
                except subprocess.TimeoutExpired:
                    print(f'{name}: running for {int((time.monotonic() - started) // 60)} min', flush=True)
        if code:
            tail = log.read_text(errors='replace').splitlines()[-40:]
            text = '\n'.join(tail)
            for secret in self.redact:
                text = text.replace(secret, '[redacted]')
            print(text, flush=True)
            raise RuntimeError(f'LineageOS step {name} failed; full log: {log}')

    def done(self, step):
        """A step marker names the manifest commit it was done for; another commit redoes the step."""
        marker = self.tree / f'.openfactory-{step}-{self.device}'
        return marker.is_file() and marker.read_text().strip() == self.commit

    def release_files(self):
        release = self.releases / self.commit
        return (release / f'{self.device}-target_files.zip', release / f'{self.device}-otatools.zip',
            release / f'{self.device}-source-manifest.xml')

    def compiled(self):
        return self.done('compiled') and all(path.is_file() for path in self.release_files())

    def prepare_cache(self):
        for path in (self.home / 'bin', self.home / 'tmp', self.logs, self.releases):
            path.mkdir(parents=True, exist_ok=True)
        give_to_builder(self.home, self.releases)
        self.tree.mkdir(exist_ok=True)
        # The synced tree is hundreds of GiB; re-owning it every build would take minutes.
        give_to_builder(self.tree, only_if_needed=True)

    def prepare(self):
        """Sync, extract vendor files and compile once per (manifest commit, device): hours under the cache lock."""
        with prepare_marker(self.cache):
            self.prepare_cache()
            if self.compiled():
                return
            require_free_space(self.cache, self.tree / 'out')
            self.ensure_source()
            self.ensure_vendor()
            self.ensure_compiled()

    def ensure_source(self):
        marker = self.tree / '.openfactory-manifest'
        if marker.is_file() and marker.read_text().strip() == self.commit:
            return
        self.step('sync', '''
git config --global user.name >/dev/null || git config --global user.name OpenFactory
git config --global user.email >/dev/null || git config --global user.email builds@openfactory.tech
git config --global color.ui false
git lfs install
# Output of an earlier commit; a retry of the same commit keeps it and builds incrementally.
rm -rf out
repo init -u "$MANIFEST_URL" -b "$COMMIT" --git-lfs --no-clone-bundle
git -C .repo/manifests fetch -q origin "refs/heads/$BRANCH"
git -C .repo/manifests merge-base --is-ancestor "$COMMIT" FETCH_HEAD
test "$(git -C .repo/manifests rev-parse HEAD)" = "$COMMIT"
repo sync --force-sync
printf '%s\\n' "$COMMIT" > .openfactory-manifest
''', variables={'MANIFEST_URL': MANIFEST_URL, 'BRANCH': BRANCH, 'COMMIT': self.commit})
        # Compiled output of earlier manifest commits is never signed again.
        for old in self.releases.glob('*'):
            if old.name != self.commit:
                shutil.rmtree(old)

    def ensure_vendor(self):
        if self.done('vendor'):
            return
        # breakfast fetches the device tree and its dependencies, then fails until the
        # vendor files exist. LineageOS pins the Google factory image they come from
        # (URL and SHA-256) in vendor/lineage/vars/<device>.
        self.step('vendor', '''
set +u
source build/envsetup.sh >/dev/null
breakfast "$DEVICE" user || true
set -u
test -x "device/google/$DEVICE/extract-files.py"
source "vendor/lineage/vars/$DEVICE"
(cd "device/google/$DEVICE" && ./extract-files.py --download-dir "$HOME/factory-images" \\
    --download-sha256 "$image_sha256" "$image_url")
rm -rf "$HOME/factory-images"
printf '%s\\n' "$COMMIT" > ".openfactory-vendor-$DEVICE"
''', variables={'DEVICE': self.device, 'COMMIT': self.commit})

    def ensure_compiled(self):
        if self.compiled():
            return
        target_files, otatools, source_manifest = self.release_files()
        with compile_lock(self.cache):
            require_free_space(self.cache, self.tree / 'out')
            self.step('compile', '''
set +u
source build/envsetup.sh >/dev/null
breakfast "$DEVICE" user
m ${LINEAGEOS_JOBS:+-j$LINEAGEOS_JOBS} target-files-package otatools-package
set -u
# Soong installs the otatools-package genrule here, not in $OUT (GrapheneOS script/finalize.sh).
built_otatools="$ANDROID_HOST_OUT/obj/ETC/otatools-packagelinux_glibc_x86_64_intermediates/otatools-packagelinux_glibc_x86_64"
built_target_files="$OUT/obj/PACKAGING/target_files_intermediates/$TARGET_PRODUCT-target_files.zip"
test -f "$built_target_files"
test -f "$built_otatools"
mkdir -p "$(dirname "$TARGET_FILES")"
cp "$built_target_files" "$TARGET_FILES"
cp "$built_otatools" "$OTATOOLS"
# The manifest pins branches; record the exact project revisions this compile used.
repo manifest -r -o "$SOURCE_MANIFEST"
rm -rf out
printf '%s\\n' "$COMMIT" > ".openfactory-compiled-$DEVICE"
''', variables={'DEVICE': self.device, 'COMMIT': self.commit, 'TARGET_FILES': target_files,
                'OTATOOLS': otatools, 'SOURCE_MANIFEST': source_manifest})

    def ensure_keys(self, keys, password):
        if (keys / 'avb_pkmd.bin').is_file():
            return
        keys.mkdir(mode=0o700, parents=True, exist_ok=True)
        give_to_builder(keys)
        # make_key prompts on stdin (blank = no passphrase); every private key is
        # then encrypted with the owner's passphrase, as GrapheneOS script/encrypt-keys does.
        self.step('keys', '''
IFS= read -r password
export password
work=$(mktemp -d /dev/shm/of-lineageos-keys.XXXXXXXXXX)
trap 'rm -rf "$work"' EXIT
cd "$work"
for key in $DEFAULT_KEYS; do
    # make_key always exits 1 through its EXIT trap; judge it by its outputs.
    printf '\\n' | "$TREE/development/tools/make_key" "$key" "$SUBJECT" >/dev/null || true
    test -s "$key.pk8"
    test -s "$key.x509.pem"
    openssl pkcs8 -topk8 -inform DER -in "$key.pk8" -outform DER -out "$KEYS/$key.pk8" -passout env:password -scrypt
    cp "$key.x509.pem" "$KEYS/"
done
openssl genrsa 4096 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out avb.pem
openssl pkcs8 -topk8 -in avb.pem -out "$KEYS/avb.pem" -passout env:password -scrypt
python3 "$TREE/external/avb/avbtool.py" extract_public_key --key avb.pem --output "$KEYS/avb_pkmd.bin"
''', cwd=keys, stdin=password + '\n', variables={'TREE': self.tree, 'KEYS': keys, 'SUBJECT': KEY_SUBJECT,
            'DEFAULT_KEYS': ' '.join((*DEFAULT_KEYS, *EXTRA_KEYS))})

    def sign(self, keys, password):
        """LineageOS signing guide: sign_target_files_apks, then ota_from_target_files; images for flashing."""
        shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir()
        give_to_builder(self.work)
        target_files, otatools, _ = self.release_files()
        self.step('sign', '''
IFS= read -r password
export password
plain=$(mktemp -d /dev/shm/of-lineageos-keys.XXXXXXXXXX)
trap 'rm -rf "$plain"' EXIT
for key in "$KEYS"/*.pk8; do
    openssl pkcs8 -inform DER -in "$key" -passin env:password \\
        | openssl pkcs8 -topk8 -outform DER -out "$plain/${key##*/}" -nocrypt
done
openssl pkcs8 -topk8 -in "$KEYS/avb.pem" -passin env:password -out "$plain/avb.pem" -nocrypt
cp "$KEYS"/*.x509.pem "$plain/"
unset password
unzip -q "$OTATOOLS"
# A fixed relative key path keeps the signed images independent of the tmpfs name.
ln -s "$plain" keys
export PATH="$TREE/prebuilts/jdk/jdk21/linux-x86/bin:$PWD/bin:$TREE/prebuilts/build-tools/linux-x86/bin:$PATH"
read -ra sign_args <<< "$SIGN_ARGS"
sign_target_files_apks -o -d keys "${sign_args[@]}" "$TARGET_FILES" signed-target_files.zip
ota_from_target_files -k keys/releasekey --block --backup=true signed-target_files.zip "$DEVICE-ota_update.zip"
img_from_target_files signed-target_files.zip "$DEVICE-img.zip"
rm -f keys
''', cwd=self.work, stdin=password + '\n', variables={'TREE': self.tree, 'KEYS': keys, 'DEVICE': self.device,
            'TARGET_FILES': target_files, 'OTATOOLS': otatools, 'SIGN_ARGS': ' '.join(signing_args(target_files))})
        return self.work

    def verify(self, work, keys):
        """Prove vbmeta and every partition it chains to use the owner's AVB key, and the OTA their release key."""
        images = work / 'images'
        with zipfile.ZipFile(work / f'{self.device}-img.zip') as archive:
            archive.extractall(images)
        give_to_builder(images)
        self.step('verify', '''
python3 "$TREE/external/avb/avbtool.py" verify_image --image vbmeta.img --follow_chain_partitions
python3 "$TREE/external/avb/avbtool.py" info_image --image vbmeta.img > vbmeta-info.txt
''', cwd=images, variables={'TREE': self.tree})
        signers = set(re.findall(r'Public key \(sha1\):\s+([0-9a-f]{40})', (images / 'vbmeta-info.txt').read_text()))
        if signers != {digest(keys / 'avb_pkmd.bin', 'sha1')}:
            raise ValueError("vbmeta or a partition it chains to is not signed with the owner's AVB key")
        with zipfile.ZipFile(work / f'{self.device}-ota_update.zip') as archive:
            if archive.read('META-INF/com/android/otacert') != (keys / 'releasekey.x509.pem').read_bytes():
                raise ValueError("OTA is not signed with the owner's release key")
        missing = [name for name in FLASHED_IMAGES if not (images / f'{name}.img').is_file()]
        if missing:
            raise ValueError(f'Signed images lack {", ".join(missing)}')
        check_mac_permissions(work / 'signed-target_files.zip', keys,
            sorted((self.tree / 'build/make/target/product/security').glob('*.x509.pem')))


def certificate_hex(path):
    """An X.509 PEM certificate as the lowercase DER hex mac_permissions.xml signers use."""
    body = re.search(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', Path(path).read_text(), re.S)
    if not body:
        raise ValueError(f'No certificate in {path}')
    return base64.b64decode(''.join(body.group(1).split())).hex()


def check_mac_permissions(signed_target_files, keys, test_certificates):
    """No SELinux signer may still name a public source-tree test certificate.

    Pixel policy also trusts Google's own certificates for presigned vendor apps
    (device/google/laguna sepolicy/certificates), so those may remain.
    """
    public = {certificate_hex(path): Path(path).name for path in test_certificates}
    if not public:
        raise ValueError('No source-tree test certificates to check mac_permissions.xml against')
    owner_platform = certificate_hex(keys / 'platform.x509.pem')
    trusted = set()
    with zipfile.ZipFile(signed_target_files) as archive:
        policies = [name for name in archive.namelist() if name.endswith('mac_permissions.xml')]
        if not policies:
            raise ValueError('The signed target files carry no mac_permissions.xml')
        for name in policies:
            signers = {signer.get('signature', '').lower()
                for signer in ElementTree.fromstring(archive.read(name)).iter('signer')}
            left = sorted(public[signer] for signer in signers & public.keys())
            if left:
                raise ValueError(f'{name} still trusts the source-tree test certificate {", ".join(left)}')
            trusted |= signers
    if owner_platform not in trusted:
        raise ValueError("No mac_permissions.xml trusts the owner's platform certificate")


def ota_name(config):
    return f'images/{config["branch"]}-{config["device"]}-ota.zip'


def install_notes(config, fingerprint):
    device = config['device']
    boot_stack = '\n'.join(f'   fastboot flash {name} images/{name}.img' for name in FLASHED_IMAGES
        if name != RECOVERY_IMAGE)
    return f'''Unofficial LineageOS build for the Google {config['model']} ({device})
Built by OpenFactory from the official LineageOS sources, {config['branch']},
manifest commit {config['manifest_commit']}.
Signed with your own release and verified boot keys. OpenFactory is not affiliated
with the LineageOS project.

This build has not been tested on a phone. Flashing, radios and updates must be
tested on the phone.

Verified boot key fingerprint (SHA-256 of avb_pkmd.bin):
{fingerprint}

First install (this erases the phone):
1. Follow https://wiki.lineageos.org/devices/{device}/install up to and including
   unlocking the bootloader. It names the stock firmware the phone needs first.
2. In bootloader mode, flash the boot images from this build:
{boot_stack}
   fastboot reboot bootloader
   fastboot flash {RECOVERY_IMAGE} images/{RECOVERY_IMAGE}.img
3. Start Recovery mode from the bootloader menu, choose Factory reset, then
   Format data / factory reset.
4. Choose Apply update, then Apply from ADB, and run
   adb -d sideload {ota_name(config)}
5. Leave the bootloader unlocked. Like official LineageOS builds, this build does
   not enforce verified boot, so a relocked phone would refuse to start it.

Updates: build the next update in OpenFactory with the same account and phone
model, then sideload it from recovery with `adb -d sideload`. Recovery also accepts
official LineageOS updates; installing one over this build changes the signing
keys and requires wiping the phone, as does any build signed with other keys.
'''


def package(config, work, keys, fingerprint, source_manifest):
    device = config['device']
    output = ROOT / 'output'
    output.mkdir(exist_ok=True)
    notes = output / 'INSTALL.txt'
    notes.write_text(install_notes(config, fingerprint))
    images = {f'images/{name}.img': work / 'images' / f'{name}.img' for name in FLASHED_IMAGES}
    files = {ota_name(config): work / f'{device}-ota_update.zip', **images, 'avb_pkmd.bin': keys / 'avb_pkmd.bin',
        'source-manifest.xml': source_manifest, 'INSTALL.txt': notes, 'LICENSE': ROOT / 'LICENSE'}
    if any(PRIVATE_KEY_NAME.search(name) for name in files):
        raise ValueError('Refusing to package private key material')
    manifest = {'schema_version': 1, 'distribution': 'lineageos', 'board': device, 'device': device,
        'model': config['model'], 'architecture': 'aarch64', 'branch': config['branch'],
        'manifest_url': config['manifest_url'], 'manifest_commit': config['manifest_commit'],
        'avb_key_sha256': fingerprint, 'avb_verified': True, 'hardware_tested': False, 'runtime_tested': False,
        'images': [{'filename': ota_name(config), 'type': 'ota'},
                   *({'filename': f'images/{name}.img', 'partition': name,
                      'type': 'recovery' if name == RECOVERY_IMAGE else 'boot'} for name in FLASHED_IMAGES)],
        'source_url': 'https://github.com/LineageOS/android',
        'builder_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        'files': {name: digest(path) for name, path in sorted(files.items())}}
    temporary = output / 'lineageos-factory.zip.tmp'
    with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, path in sorted(files.items()):
            archive.write(path, name)
        archive.writestr('manifest.json', json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    temporary.replace(output / 'lineageos-factory.zip')
    return manifest


def main(argv):
    config = read_config(ROOT / 'config/lineageos.json')
    cache = Path(os.environ.get('LINEAGEOS_CACHE_DIR') or ROOT / '.cache').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    prepare_only = argv[1:] == ['prepare']
    if not prepare_only:
        secrets, password = secrets_dir(cache)
    with (cache / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        builder = Builder(config, cache)
        if prepare_only:
            builder.prepare()
            print(json.dumps({'prepared': config['device'], 'manifest_commit': config['manifest_commit']}),
                flush=True)
            return
        if not builder.compiled():
            raise SystemExit(f"LineageOS {config['branch']} ({config['manifest_commit'][:12]}) is not compiled "
                f"for {config['device']} on this build server. Run ./build.sh prepare first; builds never compile.")
        builder.prepare_cache()
        builder.redact.append(password)
        keys = secrets / 'keys' / config['device']
        give_to_builder(secrets)
        builder.ensure_keys(keys, password)
        try:
            work = builder.sign(keys, password)
            builder.verify(work, keys)
            fingerprint = digest(keys / 'avb_pkmd.bin')
            manifest = package(config, work, keys, fingerprint, builder.release_files()[2])
        finally:
            shutil.rmtree(builder.work, ignore_errors=True)
    print(json.dumps({'artifact': 'output/lineageos-factory.zip', 'board': manifest['board'],
        'avb_key_sha256': fingerprint, 'hardware_tested': False}), flush=True)


if __name__ == '__main__':
    main(sys.argv)
