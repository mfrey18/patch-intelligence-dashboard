import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('follow-up reporting preserves a helper-restored release and rollback links remain readable with umask 077', () => {
  const result = spawnSync('python3', ['-', fileURLToPath(new URL('../ops/apply-followups.py', import.meta.url))], {
    encoding: 'utf8',
    input: String.raw`
import contextlib,hashlib,importlib.util,io,json,os,pathlib,stat,subprocess,sys,tempfile
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('followups',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with tempfile.TemporaryDirectory(prefix='patch-followups-test-') as temporary:
    root=pathlib.Path(temporary).resolve()
    for name in ['ops','logs','releases','incoming']:(root/name).mkdir()
    previous=root/'releases'/('a'*40);previous.mkdir()
    requested=root/'releases'/('b'*40)
    (root/'current').symlink_to(previous)
    archive=root/'archive';archive.write_bytes(b'tested-archive')
    commands=[]
    def run(*args,**kwargs):
        commands.append(tuple(map(str,args)))
        if pathlib.Path(args[0]).name=='deploy-release.sh':
            # Reproduce the old failed target and the helper's successful rollback.
            requested.mkdir(mode=0o500)
            (root/'current').unlink();(root/'current').symlink_to(requested)
            (root/'current').unlink();(root/'current').symlink_to(previous)
            raise subprocess.CalledProcessError(1,list(args))
        return SimpleNamespace(returncode=0)
    with patch.object(module,'ROOT',root),patch.object(module.os,'geteuid',return_value=0),patch.object(module.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=501)),patch.object(module,'root_owned'),patch.object(module,'ensure_bootstrap_idle'),patch.object(module,'current_release',side_effect=lambda:(root/'current').resolve()),patch.object(module,'run',side_effect=run),patch.object(module.subprocess,'run') as unexpected,patch.object(module,'rollback') as rollback,patch.object(module,'dashboard',return_value=({'productSeries':[{'label':'A','value':5}]},20)),contextlib.redirect_stdout(io.StringIO()):
        original_umask=os.umask(0o077)
        try:
            try:module.apply('b'*40,archive,hashlib.sha256(b'tested-archive').hexdigest())
            except subprocess.CalledProcessError:pass
            else:raise AssertionError('Failed helper reported successful setup')
        finally:os.umask(original_umask)
        unexpected.assert_not_called();rollback.assert_not_called()
    report_path=next(path for path in (root/'logs').glob('followups-*.json') if not path.name.endswith('-before.json'))
    report=json.loads(report_path.read_text())
    assert report['status']=='failed'
    assert report['deployment']=='failed-previous-release-active'
    assert report['activeRelease']==previous.name
    assert report['preDeploymentBackup']=='passed'
    assert report['bootstrap']=='not-started' and report['sshSetup']=='pending'
    assert (root/'current').resolve()==previous
    assert requested.exists(), 'Failed release must remain available for inspection'

    # Real filesystem rollback under the restrictive caller umask, without launchd.
    (root/'current').unlink();(root/'current').symlink_to(requested)
    with patch.object(module,'ROOT',root),patch.object(module,'root_owned'),patch.object(module,'run') as restart:
        original_umask=os.umask(0o077)
        try:module.rollback(previous)
        finally:os.umask(original_umask)
        restart.assert_called_once_with('/bin/launchctl','kickstart','-k','system/com.patch.api')
    assert (root/'current').resolve()==previous
    assert (root/'deployed-sha').read_text()==previous.name+'\n'
    if hasattr(os,'lchmod'):assert stat.S_IMODE((root/'current').lstat().st_mode)==0o755
    # Restore directory access for non-root TemporaryDirectory cleanup.
    requested.chmod(0o755)
print('Verified truthful helper-failure report, halted follow-ups, and readable rollback symlink')
`,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
});
