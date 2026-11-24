import collections
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('builder', ROOT / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

GOOD = {'schema_version': 1, 'device': 'frankel', 'model': 'Pixel 10', 'branch': 'lineage-24.0',
    'manifest_url': builder.MANIFEST_URL, 'manifest_commit': 'a' * 40}
PASSWORD = 'p' * 40
OWNER_SHA1 = hashlib.sha1(b'owner-avb-key').hexdigest()
Usage = collections.namedtuple('Usage', 'total used free')


class FakeAccount:
    pw_uid, pw_gid = 990, 990


def write_keys(keys):
    keys.mkdir(parents=True)
    (keys / 'avb_pkmd.bin').write_bytes(b'owner-avb-key')
    (keys / 'releasekey.x509.pem').write_bytes(b'release-cert')


def write_signed(work, device='frankel', *, otacert=b'release-cert', images=builder.FLASHED_IMAGES):
    """What the sign step leaves behind: the OTA package and img_from_target_files output."""
    work.mkdir(parents=True)
    with zipfile.ZipFile(work / f'{device}-ota_update.zip', 'w') as archive:
        archive.writestr('META-INF/com/android/otacert', otacert)
        archive.writestr('payload.bin', b'payload')
    with zipfile.ZipFile(work / f'{device}-img.zip', 'w') as archive:
        archive.writestr('vbmeta.img', b'vbmeta')
        for name in images:
            archive.writestr(f'{name}.img', name.encode())


def compile_release(run):
    """Mark a fake compile of the pinned commit as done."""
    run.tree.mkdir(parents=True, exist_ok=True)
    for step in ('vendor', 'compiled'):
        (run.tree / f'.openfactory-{step}-{run.device}').write_text(run.commit + '\n')
    (run.tree / '.openfactory-manifest').write_text(run.commit + '\n')
    for path in run.release_files():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'zip')


class ConfigTests(unittest.TestCase):
    def test_accepts_pinned_commit_and_rejects_unsafe_or_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lineageos.json'
            path.write_text(json.dumps(GOOD))
            self.assertEqual(builder.read_config(path), GOOD)
            for change in [{'device': '../x'}, {'device': 'Frankel'}, {'branch': 'lineage-23.2'},
                    {'branch': 'main'}, {'manifest_url': 'https://example.invalid/android.git'},
                    {'manifest_commit': 'HEAD'}, {'manifest_commit': 'A' * 40}, {'model': 'Pixel; id'},
                    {'schema_version': 2}, {'tag': '2026110800'}]:
                path.write_text(json.dumps({**GOOD, **change}))
                with self.assertRaises(ValueError):
                    builder.read_config(path)
            path.write_text(json.dumps({key: value for key, value in GOOD.items() if key != 'branch'}))
            with self.assertRaises(ValueError):
                builder.read_config(path)
            path.write_text('[]')
            with self.assertRaises(ValueError):
                builder.read_config(path)

    def test_secrets_must_live_outside_workspace_and_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            cache, secrets = Path(directory) / 'cache', Path(directory) / 'secrets'
            cache.mkdir()
            secrets.mkdir()
            (secrets / 'passphrase').write_text(PASSWORD + '\n')
            with patch.dict(os.environ, {'LINEAGEOS_SECRETS_DIR': str(secrets)}):
                self.assertEqual(builder.secrets_dir(cache), (secrets.resolve(), PASSWORD))
            inside = cache / 'secrets'
            inside.mkdir()
            (inside / 'passphrase').write_text(PASSWORD)
            for value in ['', str(inside), str(ROOT), str(Path(directory) / 'missing')]:
                with patch.dict(os.environ, {'LINEAGEOS_SECRETS_DIR': value}):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        builder.secrets_dir(cache)
            (secrets / 'passphrase').write_text('short')
            with patch.dict(os.environ, {'LINEAGEOS_SECRETS_DIR': str(secrets)}):
                with self.assertRaises(ValueError):
                    builder.secrets_dir(cache)


class PrivilegeTests(unittest.TestCase):
    def test_root_drops_to_build_account_with_clean_environment(self):
        with patch.object(builder.os, 'geteuid', return_value=0), \
                patch.object(builder.pwd, 'getpwnam', return_value=FakeAccount) as account, \
                patch.dict(os.environ, {'LINEAGEOS_SECRETS_DIR': '/run/secret', 'LINEAGEOS_JOBS': '24'}):
            argv = builder.builder_argv(Path('/cache/home'))
        account.assert_called_with('of-lineageos')
        for flag in ['setpriv', '--reuid=990', '--regid=990', '--clear-groups', '--no-new-privs',
                '--inh-caps=-all', '--bounding-set=-all', 'env', '-i', 'LINEAGEOS_JOBS=24']:
            self.assertIn(flag, argv)
        self.assertFalse(any('/run/secret' in item or 'SECRETS' in item for item in argv))

    def test_passphrase_only_on_stdin_and_redacted_from_failure_output(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            run = builder.Builder(GOOD, cache)
            run.logs.mkdir()
            run.redact.append(PASSWORD)
            seen = []
            real_popen = subprocess.Popen

            def popen(argv, **kwargs):
                seen.append(argv)
                return real_popen(argv, **kwargs)

            output = io.StringIO()
            with patch.object(builder.subprocess, 'Popen', popen), contextlib.redirect_stdout(output):
                with self.assertRaises(RuntimeError):
                    run.step('sign', 'IFS= read -r password\necho "using $password"\nexit 3\n',
                        cwd=cache, stdin=PASSWORD + '\n')
            self.assertFalse(any(PASSWORD in item for item in seen[0]))
            self.assertIn('using [redacted]', output.getvalue())
            self.assertNotIn(PASSWORD, output.getvalue())


class PrepareTests(unittest.TestCase):
    def prepare(self, directory, *, free=builder.MIN_FREE_BYTES, run=None):
        run = run or builder.Builder(GOOD, Path(directory) / 'cache')
        self.steps = []
        with patch.object(builder, 'COMPILE_LOCK', Path(directory) / '.android-compile.lock'), \
                patch.object(builder.shutil, 'disk_usage', return_value=Usage(0, 0, free)), \
                patch.object(run, 'step', lambda name, *a, **k: self.steps.append(name)):
            run.prepare()
        return self.steps

    def test_steps_run_in_upstream_order_once_per_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.prepare(directory), ['sync', 'vendor', 'compile'])
            run = builder.Builder(GOOD, Path(directory) / 'cache')
            compile_release(run)
            self.assertEqual(self.prepare(directory, run=run), [])

    def test_a_new_commit_moves_the_one_tree_and_drops_old_compiles(self):
        with tempfile.TemporaryDirectory() as directory:
            old = builder.Builder(GOOD, Path(directory) / 'cache')
            compile_release(old)
            bumped = builder.Builder({**GOOD, 'manifest_commit': 'b' * 40}, Path(directory) / 'cache')
            self.assertEqual(bumped.tree, old.tree)
            self.assertFalse(bumped.compiled())
            self.assertEqual(self.prepare(directory, run=bumped), ['sync', 'vendor', 'compile'])
            self.assertFalse((old.releases / GOOD['manifest_commit']).exists())

    def test_refuses_to_compile_below_300_gib_free(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit) as refused:
                self.prepare(directory, free=builder.MIN_FREE_BYTES - 1)
            self.assertIn('300 GiB needed', str(refused.exception))
            self.assertEqual(self.steps, [])

    def test_refuses_while_another_android_compile_holds_the_host_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory) / '.android-compile.lock').open('a') as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                with self.assertRaises(SystemExit) as refused:
                    self.prepare(directory)
            self.assertIn('another Android compile', str(refused.exception))
            self.assertEqual(self.steps, [])
            self.assertEqual(self.prepare(directory), ['sync', 'vendor', 'compile'])

    def test_a_build_run_refuses_when_the_commit_is_not_compiled(self):
        with tempfile.TemporaryDirectory() as directory:
            root, cache, secrets = Path(directory) / 'repo', Path(directory) / 'cache', Path(directory) / 'secrets'
            (root / 'config').mkdir(parents=True)
            (root / 'config/lineageos.json').write_text(json.dumps(GOOD))
            secrets.mkdir()
            (secrets / 'passphrase').write_text(PASSWORD + '\n')
            environment = {'LINEAGEOS_CACHE_DIR': str(cache), 'LINEAGEOS_SECRETS_DIR': str(secrets)}
            with patch.object(builder, 'ROOT', root), patch.dict(os.environ, environment), \
                    patch.object(builder.Builder, 'step', side_effect=AssertionError('compiled in a build slot')):
                with self.assertRaises(SystemExit) as refused:
                    builder.main(['build.py'])
            self.assertIn('not compiled for frankel', str(refused.exception))
            self.assertIn('prepare', str(refused.exception))


class SigningArgsTests(unittest.TestCase):
    def test_every_source_tree_key_moves_to_the_owner_keys(self):
        security = 'build/make/target/product/security'
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / 'frankel-target_files.zip'
            with zipfile.ZipFile(target_files, 'w') as archive:
                archive.writestr('META/misc_info.txt', '\n'.join([
                    f'default_system_dev_certificate={security}/testkey', 'avb_enable=true',
                    'avb_vbmeta_key_path=external/avb/test/data/testkey_rsa4096.pem',
                    'avb_vbmeta_system_key_path=external/avb/test/data/testkey_rsa2048.pem',
                    'avb_boot_key_path=external/avb/test/data/testkey_rsa2048.pem', 'avb_boot_algorithm=SHA256_RSA2048']))
                archive.writestr('META/apkcerts.txt', '\n'.join([
                    f'name="Settings.apk" certificate="{security}/platform.x509.pem" private_key="{security}/platform.pk8"',
                    f'name="Browser.apk" certificate="{security}/testkey.x509.pem" private_key="{security}/testkey.pk8"',
                    'name="ServiceWifiResources.apk" certificate="packages/modules/Wifi/resources.x509.pem" '
                    'private_key="packages/modules/Wifi/resources.pk8" partition="system"',
                    'name="Camera.apk" certificate="PRESIGNED" private_key=""', '']))
                archive.writestr('META/apexkeys.txt', '\n'.join([
                    'name="com.android.adbd.apex" public_key="a.avbpubkey" private_key="a.pem" '
                    'container_certificate="a.x509.pem" container_private_key="a.pk8" partition="system" sign_tool=""',
                    'name="com.google.pixel.camera.hal.apex" public_key="PRESIGNED" private_key="PRESIGNED" '
                    'container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="vendor"']))
            args = builder.signing_args(target_files)
        pairs = list(zip(args[::2], args[1::2]))
        self.assertEqual([value for flag, value in pairs if flag == '--extra_apks'],
            ['ServiceWifiResources.apk=keys/releasekey', 'com.android.adbd.apex=keys/releasekey'])
        self.assertEqual([value for flag, value in pairs if flag == '--extra_apex_payload_key'],
            ['com.android.adbd.apex=keys/avb.pem'])
        self.assertEqual([value for flag, value in pairs if flag == '--avb_extra_custom_image_key'],
            ['boot=keys/avb.pem', 'vbmeta=keys/avb.pem', 'vbmeta_system=keys/avb.pem'])
        self.assertEqual({value for flag, value in pairs if flag == '--avb_extra_custom_image_algorithm'},
            {'boot=SHA256_RSA4096', 'vbmeta=SHA256_RSA4096', 'vbmeta_system=SHA256_RSA4096'})

    def test_rejects_names_that_could_break_the_argument_list(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / 'frankel-target_files.zip'
            with zipfile.ZipFile(target_files, 'w') as archive:
                archive.writestr('META/misc_info.txt', '')
                archive.writestr('META/apkcerts.txt',
                    'name="Bad *.apk" certificate="x/y.x509.pem" private_key="x/y.pk8"\n')
                archive.writestr('META/apexkeys.txt', '')
            with self.assertRaises(ValueError):
                builder.signing_args(target_files)


class VerifyAndPackageTests(unittest.TestCase):
    def verify(self, directory, signers=(OWNER_SHA1,), **signed):
        run = builder.Builder(GOOD, Path(directory))
        keys = Path(directory) / 'keys'
        write_keys(keys)
        write_signed(run.work, **signed)

        def step(name, script, *, cwd=None, **kwargs):
            (cwd / 'vbmeta-info.txt').write_text(''.join(f'Public key (sha1):        {sha1}\n' for sha1 in signers))

        with patch.object(run, 'step', step):
            run.verify(run.work, keys)

    def test_accepts_images_signed_with_the_owner_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            self.verify(directory, signers=(OWNER_SHA1, OWNER_SHA1))

    def test_rejects_a_foreign_chained_key_release_key_or_missing_boot_image(self):
        for change in [{'signers': (OWNER_SHA1, 'f' * 40)}, {'signers': ()}, {'otacert': b'other'},
                {'images': ('boot', 'dtbo', 'vendor_kernel_boot')}]:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.verify(directory, **change)

    def test_package_covers_every_member_and_never_private_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys = root / 'keys'
            write_keys(keys)
            (keys / 'releasekey.pk8').write_bytes(b'secret')
            (keys / 'avb.pem').write_bytes(b'secret')
            work = root / 'sign-frankel'
            write_signed(work)
            with zipfile.ZipFile(work / 'frankel-img.zip') as archive:
                archive.extractall(work / 'images')
            source_manifest = root / 'frankel-source-manifest.xml'
            source_manifest.write_text('<manifest/>\n')
            (root / 'LICENSE').write_text('MIT')
            fingerprint = hashlib.sha256(b'owner-avb-key').hexdigest()
            with patch.object(builder, 'ROOT', root), \
                    patch.object(builder.subprocess, 'check_output', return_value=b'c' * 40):
                manifest = builder.package(GOOD, work, keys, fingerprint, source_manifest)
            with zipfile.ZipFile(root / 'output/lineageos-factory.zip') as archive:
                names = set(archive.namelist())
                self.assertEqual(set(manifest['files']), names - {'manifest.json'})
                self.assertFalse(any(builder.PRIVATE_KEY_NAME.search(name) for name in names))
                self.assertEqual(json.loads(archive.read('manifest.json')), manifest)
                notes = archive.read('INSTALL.txt').decode()
        for key, value in {'schema_version': 1, 'distribution': 'lineageos', 'board': 'frankel', 'device': 'frankel',
                'architecture': 'aarch64', 'branch': 'lineage-24.0', 'manifest_commit': GOOD['manifest_commit'],
                'manifest_url': GOOD['manifest_url'], 'avb_verified': True, 'avb_key_sha256': fingerprint,
                'builder_revision': 'c' * 40, 'hardware_tested': False, 'runtime_tested': False}.items():
            self.assertEqual(manifest[key], value, key)
        self.assertEqual(manifest['files']['avb_pkmd.bin'], fingerprint)
        self.assertIn('source-manifest.xml', manifest['files'])
        images = {item['filename']: item['type'] for item in manifest['images']}
        self.assertEqual(images, {'images/lineage-24.0-frankel-ota.zip': 'ota', 'images/boot.img': 'boot',
            'images/dtbo.img': 'boot', 'images/vendor_kernel_boot.img': 'boot', 'images/vendor_boot.img': 'recovery'})
        self.assertTrue(set(images) <= set(manifest['files']))
        self.assertIn(fingerprint, notes)

    def test_install_notes_state_what_the_build_is_and_is_not(self):
        notes = ' '.join(builder.install_notes(GOOD, 'f' * 64).split())
        for phrase in ['Unofficial LineageOS build', 'from the official LineageOS sources',
                'Signed with your own release and verified boot keys',
                'not affiliated with the LineageOS project',
                'Flashing, radios and updates must be tested on the phone',
                'fastboot flash vendor_boot images/vendor_boot.img',
                'adb -d sideload images/lineage-24.0-frankel-ota.zip', GOOD['manifest_commit']]:
            self.assertIn(phrase, notes)

    def test_gitignore_keeps_keys_and_outputs_out_of_build_branches(self):
        ignored = (ROOT / '.gitignore').read_text().split()
        for pattern in ['keys/*/', '*.pk8', '*.pem', 'output/', 'config/lineageos.json']:
            self.assertIn(pattern, ignored)


if __name__ == '__main__':
    unittest.main()
