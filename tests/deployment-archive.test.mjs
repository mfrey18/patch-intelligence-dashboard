import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('deployment extraction rejects unsafe members and ignores archive permissions and owners', () => {
  const result = spawnSync('python3', ['-', fileURLToPath(new URL('../ops/deploy-release.sh', import.meta.url))], {
    encoding: 'utf8',
    input: String.raw`
import ast,io,os,pathlib,stat,sys,tarfile,tempfile

script=pathlib.Path(sys.argv[1]).read_text().split("<<'PY'\n",1)[1].split("\nPY",1)[0]
with tempfile.TemporaryDirectory(prefix='patch-archive-test-') as temporary:
    base=pathlib.Path(temporary)
    class IsolateStaging(ast.NodeTransformer):
        def visit_Constant(self,node):
            if node.value=='/Library/PatchIntelligence/staging':
                node.value=str(base/'staging')
            return node
    code=compile(ast.fix_missing_locations(IsolateStaging().visit(ast.parse(script))),'deploy-release-extraction','exec')
    def execute(archive,destination):
        sys.argv=['extract',str(archive),str(destination)]
        exec(code,{'__name__':'__main__'})
    def archive_file(path,members):
        with tarfile.open(path,'w:gz') as archive:
            for name,kind in members:
                entry=tarfile.TarInfo(name)
                entry.type=kind
                entry.uid=501;entry.gid=20;entry.uname='untrusted';entry.gname='untrusted'
                entry.mode=0o7777
                payload=b'reviewed release data\n' if kind==tarfile.REGTYPE else b''
                entry.size=len(payload)
                if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):entry.linkname='../escape'
                archive.addfile(entry,io.BytesIO(payload))
    valid=base/'valid.tar.gz'
    archive_file(valid,[('nested',tarfile.DIRTYPE),('nested/app',tarfile.REGTYPE)])
    original_chown=tarfile.TarFile.chown
    checked=[]
    def inspect_owner(self,member,target,*args,**kwargs):
        assert (member.uid,member.gid,member.uname,member.gname)==(0,0,'','')
        assert member.mode==0o755
        checked.append(member.name)
        return original_chown(self,member,target,*args,**kwargs)
    tarfile.TarFile.chown=inspect_owner
    try:
        execute(valid,base/'release')
    finally:
        tarfile.TarFile.chown=original_chown
    assert set(checked)=={'nested','nested/app'}
    assert (base/'release/nested/app').read_bytes()==b'reviewed release data\n'
    assert stat.S_IMODE((base/'release/nested/app').stat().st_mode)==0o755
    assert stat.S_IMODE((base/'release/nested').stat().st_mode)==0o755

    for index,(name,kind) in enumerate([
        ('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),
        ('nested/link',tarfile.SYMTYPE),('nested/hardlink',tarfile.LNKTYPE),
        ('nested/fifo',tarfile.FIFOTYPE),('nested/device',tarfile.CHRTYPE),
    ]):
        archive=base/('invalid%d.tar.gz'%index)
        destination=base/('rejected%d'%index)
        archive_file(archive,[(name,kind)])
        try:execute(archive,destination)
        except SystemExit as error:assert str(error)=='Unsafe release archive'
        else:raise AssertionError('Unsafe archive was accepted: '+name)
        assert not destination.exists()

    link=base/'upload-link.tar.gz';link.symlink_to(valid)
    try:execute(link,base/'link-release')
    except OSError:pass
    else:raise AssertionError('Upload symlink accepted')

    # Changing the upload after the root snapshot exists must not change what
    # gets validated or extracted. Only the temporary snapshot is trusted.
    original_open=tarfile.open
    def replace_upload(*args,**kwargs):
        assert 'fileobj' in kwargs
        valid.write_bytes(b'replaced upload')
        return original_open(*args,**kwargs)
    tarfile.open=replace_upload
    try:execute(valid,base/'snapshot-release')
    finally:tarfile.open=original_open
    assert (base/'snapshot-release/nested/app').read_bytes()==b'reviewed release data\n'
print('Verified metadata sanitization, traversal/link/device rejection, and immutable extraction snapshot')
`,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
});
