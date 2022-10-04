# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import base64
import logging
import os
import paramiko
import pipes
import re
import stat
import subprocess
import sys
import tarfile
import uuid

from ..conf import project
from .strings import mask_string


OUTFMT = '---- {type} ----\n{content}'
LOG = logging.getLogger('kanzo.backend')


def execute(cmd, workdir=None, can_fail=True, mask_list=None,
            use_shell=False, log=True):
    """
    Runs shell command cmd. If can_fail is set to True RuntimeError is raised
    if command returned non-zero return code. Otherwise returns return code
    and content of stdout.
    """
    mask_list = mask_list or []
    repl_list = [("'", "'\\''")]

    if not isinstance(cmd, str):
        masked = ' '.join((pipes.quote(i) for i in cmd))
    else:
        masked = cmd
    masked = mask_string(masked, mask_list, repl_list)
    if log:
        LOG.info('Executing command: %s' % masked)

    proc = subprocess.Popen(cmd, cwd=workdir, shell=use_shell, close_fds=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()

    if log:
        for tp, ot in (('stdout', out), ('stderr', err)):
            LOG.info(
                OUTFMT.format(
                    type=tp, content=mask_string(ot, mask_list, repl_list)
                )
            )
    if proc.returncode and can_fail:
        raise RuntimeError('Failed to execute command: %s' % masked)
    return proc.returncode, out, err


class IgnorePolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, *args, **kwargs):
        return


class RemoteShell(object):
    _connections = {}

    username = project.DEFAULT_SSH_USER
    sshkey = project.DEFAULT_SSH_PRIVATE_KEY
    port = project.DEFAULT_SSH_PORT

    def __init__(self, host):
        self.host = host
        if host in self._connections:
            self._client = self._connections[host]
        else:
            self.reconnect()

    def _get_key(self, key_type):
        if key_type == 'private' and self.sshkey.endswith('.pub'):
            path = self.sshkey[:-4]
        elif key_type == 'public' and not self.sshkey.endswith('.pub'):
            path = '%s.pub' % self.sshkey
        else:
            path = self.sshkey
        LOG.debug('Using ssh-key: {}'.format(path))
        return os.path.abspath(os.path.expanduser(path))

    def _register(self):
        if self.host in self._connections:
            # ssh-key should be in place on host already, so do nothing
            LOG.debug('Skipping ssh-key register process for host %s.'
                         % self.host)
            return
        if not self.sshkey:
            raise ValueError('Attribute sshkey has to be set to connect '
                             'to host %s.' % self.host)
        with open(self._get_key('public')) as kfile:
            data = kfile.read().strip()
        # register ssh-key to host
        script = ['mkdir -p ~/.ssh',
                  'chmod 500 ~/.ssh',
                  'grep "%(data)s" ~/.ssh/authorized_keys > '
                        '/dev/null 2>&1 || '
                        'echo "%(data)s" >> ~/.ssh/authorized_keys' % locals(),
                  'chmod 400 ~/.ssh/authorized_keys',
                  'restorecon -r ~/.ssh']
        self.run_script(
            script, description='ssh-key register on host {}'.format(self.host)
        )

    def reconnect(self):
        """Establish connection to host."""
        self._register()
        LOG.debug('Reconnecting to host {}'.format(self.host))
        # create connection to host
        clt = paramiko.SSHClient()
        clt.set_missing_host_key_policy(IgnorePolicy())
        clt.set_log_channel('kanzo.backend')
        try:
            clt.connect(self.host, port=self.port, username=self.username,
                        key_filename=self._get_key('private'))
        except paramiko.SSHException as ex:
            raise RuntimeError('Failed to (re)connect to host %s' % self.host)
        self._connections[self.host] = self._client = clt
        # XXX: following should not be required, so commenting for now
        #clt.get_transport().set_keepalive(10)

    def _process_output(self, otype, channel, mlist, rlist, log=True):
        output = channel.readlines()
        if log:
            LOG.info(
                OUTFMT.format(
                    type=otype,
                    content=mask_string('\n'.join(output), mlist, rlist)
                )
            )
        return '\n'.join(output)

    def execute(self, cmd, can_fail=True, mask_list=None, log=True):
        """Executes given command on remote host. Raises RuntimeError if
        command failed and if can_fail is True. Logging executed command,
        content of stdout and content of stderr if log is True. Parameter
        mask_list should contain words which is supposed to be masked
        in log messages. Returns (return code, content of stdout, content
        of stderr).
        """
        mask_list = mask_list or []
        repl_list = [("'", "'\\''")]
        masked = mask_string(cmd, mask_list, repl_list)
        if log:
            LOG.info(
                '[{self.host}] Executing command: {masked}'.format(**locals())
            )
        retry = project.SHELL_RECONNECT_RETRY or 1
        while retry:
            try:
                retry -= 1
                chin, chout, cherr = self._client.exec_command(cmd)
            except paramiko.SSHException as ex:
                if log:
                    LOG.warning(
                        '[{self.host}] Failed to run command:'
                        '\n{masked}'.format(**locals())
                    )
                if not retry:
                    trc = str(ex)
                    msg = (
                        'No retries left. Following error appeared:\n'
                        '\n{trc}'.format(**locals())
                    )
                    LOG.error(msg)
                    raise RuntimeError(msg)
                # in case any error reconnect and try again
                self.reconnect()
                LOG.debug(
                    'Retries left: {retry}. Running command again.'.format(
                        **locals()
                    )
                )

        stdout = self._process_output(
            'stdout', chout, mask_list, repl_list, log=log
        )
        stderr = self._process_output(
            'stderr', cherr, mask_list, repl_list, log=log
        )
        rc = chout.channel.recv_exit_status()
        if rc and can_fail:
            raise RuntimeError(
                '[{self.host}] Failed to run command:'
                '\n{masked}\nstdout:\n{stdout}\n'
                'stderr:\n{stderr}'.format(**locals())
            )
        return rc, stdout, stderr

    def run_script(self, script, can_fail=True, mask_list=None,
                   log=False, description=None):
        """Runs given script on remote host. Script should be list where each
        item represents one command. Raises RuntimeError if command failed
        and if can_fail is True. Logging executed command, content of stdout
        and content of stderr if log is True. Parameter mask_list should
        contain words which is supposed to be masked in log messages.
        Returns (return code, content of stdout, content of stderr).
        """
        mask_list = mask_list or []
        repl_list = [("'", "'\\''")]
        desc = description or (
            '{}...'.format(mask_string(script[0]), mask_list, repl_list)
        )
        err_msg = '[{self.host}] Failed to run script:\n{desc}\n{stderr}'

        _script = ['function script_trap(){ exit $? ; }',
                   'trap script_trap ERR']
        _script.extend(script)

        if log:
            LOG.info(
                '[{self.host}] Executing script: {desc}'.format(**locals())
            )
        proc = subprocess.Popen(
            [
                'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-p', str(self.port),
                    '-i', self._get_key('private'),
                    '{}@{}'.format(self.username, self.host),
                    'bash -x'
            ],
            close_fds=True,
            shell=False,
            universal_newlines=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate('\n'.join(_script))

        if log:
            LOG.info(
                'stdout:\n{}'.format(mask_string(stdout, mask_list, repl_list))
            )
            LOG.info(
                'stderr:\n{}'.format(mask_string(stderr, mask_list, repl_list))
            )
        if proc.returncode and can_fail:
            raise RuntimeError(
                'Failed to run script: {desc}'.format(**locals())
            )
        return proc.returncode, stdout, stderr


class BaseTransfer(object):
    def __init__(self, host, remote_tmpdir, local_tmpdir):
        self._shell = RemoteShell(host)
        self._remote_tmpdir = remote_tmpdir
        self._local_tmpdir = local_tmpdir

    def send(self, source, destination):
        """Packs given local source directory/file to tarball, transfers it and
        unpacks to given remote destination directory.
        """
        # packing
        if not os.path.exists(source):
            raise ValueError(
                'Given local path does not exists: '
                '{source}'.format(**locals())
            )
        tarball = self._pack_local(source)
        # preparation
        tmpdir = self._check_remote_tmpdir()
        tmpfile = os.path.join(tmpdir, os.path.basename(tarball))
        # transfer and unpack
        try:
            self._transfer(tarball, tmpdir, sourcetype='local')
            self._unpack_remote(tmpfile, destination)
        finally:
            os.unlink(tarball)
            self._shell.execute('rm -f {tmpfile}'.format(**locals()))

    def receive(self, source, destination):
        """Packs given remote source directory/file to tarball, transfers it
        and unpacks to given local destination directory.
        """
        # packing
        rc, stdout, stderr = self._shell.execute(
            '[ -e "{source}" ]'.format(**locals()),
            can_fail=False
        )
        if rc:
            host = self._shell.host
            raise ValueError(
                'Given path on host {host} does not exists: '
                '{source}'.format(**locals())
            )
        tarball = self._pack_remote(source)
        # preparation
        tmpdir = self._check_local_tmpdir()
        tmpfile = os.path.join(tmpdir, os.path.basename(tarball))
        # transfer and unpack
        try:
            self._transfer(tarball, tmpdir, sourcetype='remote')
            self._unpack_local(tmpfile, destination)
        finally:
            try:
                os.unlink(tmpfile)
            except FileNotFoundError:
                pass
            self._shell.execute('rm -fr {tarball}'.format(**locals()))

    def _transfer(self, source, destination, sourcetype):
        """Child class has to implement this method."""
        raise NotImplementedError()

    def _check_local_tmpdir(self):
        os.makedirs(self._local_tmpdir, mode=0o700, exist_ok=True)
        return self._local_tmpdir

    def _check_remote_tmpdir(self):
        tmpdir = self._remote_tmpdir
        self._shell.execute(
            'mkdir -p --mode=0700 {tmpdir}'.format(**locals())
        )
        return tmpdir

    def _pack_local(self, path):
        tmpdir = self._check_local_tmpdir()
        packpath = os.path.join(
            tmpdir, 'transfer-{0}.tar.gz'.format(uuid.uuid4().hex[:8])
        )
        with tarfile.open(packpath, mode='w:gz') as pack:
            pack.add(path, arcname=os.path.basename(path))
        os.chmod(packpath, stat.S_IRUSR | stat.S_IWUSR)
        return packpath

    def _pack_remote(self, path):
        packpath = os.path.join(
            self._check_remote_tmpdir(),
            'transfer-{0}.tar.gz'.format(uuid.uuid4().hex[:8])
        )
        prefix = '-C {0}'.format(os.path.dirname(path))
        path = os.path.basename(path)
        self._shell.execute(
            'tar {prefix} -cpzf {packpath} {path}'.format(**locals())
        )
        return packpath

    def _unpack_local(self, path, destination):
        with tarfile.open(path, mode='r') as pack:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(pack, path=destination)

    def _unpack_remote(self, path, destination):
        self._shell.execute(
            'mkdir -p --mode=0700 {destination} && '
            'tar -C {destination} -xpzf {path}'.format(**locals())
        )


class SCPTransfer(BaseTransfer):
    """Tranfer files via scp."""
    def _transfer(self, source, destination, sourcetype):
        cmd = [
            'scp',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-P', str(self._shell.port),
            '-i', self._shell._get_key('private'),
        ]
        if sourcetype == 'local':
            cmd.append('{src} {user}@[{host}]:{dest}')
        else:
            cmd.append('{user}@[{host}]:{src} {dest}')
        rc, out, err = execute(
            ' '.join(cmd).format(
                user=self._shell.username,
                host=self._shell.host,
                src=source,
                dest=destination,
            ),
            use_shell=True
        )


class SFTPTransfer(BaseTransfer):
    """Transfer files via SFTP client."""
    def _transfer(self, source, destination, sourcetype):
        dest = os.path.join(destination, os.path.basename(source))
        try:
            sftp = self._shell._client.open_sftp()
            if sourcetype == 'local':
                direction = sftp.put
            else:
                direction = sftp.get
            direction(source, dest)
        finally:
            sftp.close()
