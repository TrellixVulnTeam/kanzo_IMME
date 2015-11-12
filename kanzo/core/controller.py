# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import collections
import greenlet
import logging
import tempfile

from ..conf import Config, project, get_hosts
from ..utils import shell, decorators

from . import drones
from . import plugins
from . import puppet


LOG = logging.getLogger('kanzo.backend')


PluginData = collections.namedtuple(
    'PluginData', [
        'name',
        'modules',
        'resources',
        'init_steps',
        'prep_steps',
        'plan_steps',
        'clean_steps',
    ]
)


def wait_for_runners(runners):
    """Switches between given set of runners until all are finished."""
    for run in list(runners):
        if run.dead:
            runners.remove(run)
        else:
            run.switch()


class Controller(object):
    """Master class which is driving the installation process."""
    def __init__(self, config, work_dir=None, remote_tmpdir=None,
                 local_tmpdir=None):
        self._callbacks = {}
        self._messages = []
        self._tmpdir = tempfile.mkdtemp(prefix='deploy-', dir=work_dir)

        # loads config file
        self._plugin_modules = plugins.load_all_plugins()
        self._config = Config(
            config, plugins.meta_builder(self._plugin_modules)
        )
        # load all relevant information from plugins

        self._plugins = []
        for plug in self._plugin_modules:
            # load plugin data
            self._plugins.append(
                PluginData(
                    name=plug.__name__,
                    modules=getattr(plug, 'MODULES', []),
                    resources=getattr(plug, 'RESOURCES', []),
                    init_steps=getattr(plug, 'INITIALIZATION', []),
                    prep_steps=getattr(plug, 'PREPARATION', []),
                    plan_steps=getattr(plug, 'DEPLOYMENT', []),
                    clean_steps=getattr(plug, 'CLEANUP', []),
                )
            )
            LOG.debug('Loaded plugin {0}'.format(plug))

        # creates drone for each deploy host
        self._drones = {}
        self._info = {}
        for host in get_hosts(self._config):
            # connect to host to solve ssh keys as first step
            shell.RemoteShell(host)
            self._drones[host] = drones.Drone(
                host, self._config, self._messages,
                work_dir=work_dir,
                remote_tmpdir=remote_tmpdir,
                local_tmpdir=local_tmpdir,
            )

        # register resources and modules to drones
        for plug in self._plugins:
            for drone in self._drones:
                for resource in plug.resources:
                    drone.add_resource(resource)
                for module in plug.modules:
                    drone.add_module(module)

        # initialize plan for Puppet runs
        self._plan = {
            'manifests': collections.OrderedDict(),
            'dependecy': {},
            'waiting': set(),
            'in-progress': set(),
            'finished': set(),
        }

    def _iter_phase(self, phase):
        for plugin in self._plugins:
            for step in getattr(plugin, '{}_steps'.format(phase)):
                yield step

    def _run_phase(self, phase, timeout=None, debug=False):

        def _install_puppet(drone):
            parent = greenlet.getcurrent().parent
            drone.init_host()
            parent.switch()
            self._info[drone.host] = drone.discover()
            parent.switch()
            drone.configure()

        # phase run
        self._callbacks['status']('phase', phase, 'start')
        for step in self._iter_phase(phase):
            self._callbacks['status']('step', step.func_name, 'start')
            if phase == 'plan':
                # prepare Puppet runs plan
                records = step(
                    config=self._config,
                    info=self._info,
                    messages=self._messages
                )
                records = records or []
                for host, manifest, marker, prereqs in records:
                    self._drones[host].add_manifest(manifest)
                    self._plan['waiting'].add(marker)
                    self._plan['manifests'].setdefault(marker, []).append(
                        (host, manifest)
                    )
                    self._plan['dependency'].setdefault(marker, set()).update(
                        prereqs or set()
                    )
            else:
                runners = set()
                for drone in self._drones.values():
                    run = greenlet.greenlet(step)
                    runners.add(run)
                    run.switch(
                        shell=drone._shell,
                        config=self._config,
                        info=drone.info,
                        messages=self._messages
                    )
                wait_for_runners(runners)
            self._callbacks['status']('step', step.func_name, 'end')
        # phase post-run
        runners = set()
        for drone in self._drones.values():
            if phase == 'init':
                # install and configure Puppet on hosts and run discover
                run = greenlet.greenlet(_install_puppet)
            elif phase == 'plan':
                # prepare deployment builds
                run = greenlet.greenlet(drone.make_build)
            else:
                break
            runners.add(run)
            run.switch(drone)
        wait_for_runners(runners)
        self._callbacks['status']('phase', phase, 'end')

    def run_init(self, timeout=None, debug=False):
        """Completely initialize and prepare deploy hosts

        As first 'init' phase is executed. After that Puppet is installed
        on all host and hosts' info is discovered. After that 'prep' phase
        is executed and as last phase 'plan' is executed. Deployment builds
        are built and sent to hosts at the end.
        """
        self.run_phase('init', timeout=timeout, debug=debug)
        self.run_phase('prep', timeout=timeout, debug=debug)
        self.run_phase('plan', timeout=timeout, debug=debug)

    def run_deployment(self, timeout=None, debug=False):
        """Run planned deployment."""
        self._callbacks['status']('phase', 'deployment', 'start')
        runners = {}
        while self._plan['waiting'] or self._plan['in-progress']:
            # initiate deployment
            for marker, manifests in self._plan['manifests']:
                # skip finished markers
                if marker in self._plan['finished']:
                    continue
                # skip markers waiting for dependency
                reqs = self._plan['dependency'][marker] - self._plan['finished']
                if reqs:
                    LOG.debug(
                        'Marked deployment "{marker}" is waiting '
                        'for prerequisite deployments to finish: '
                        '{reqs}'.format(**locals())
                    )
                    continue
                # initiate marker deployment
                if marker not in runners:
                    LOG.debug(
                        'Initiating marked deployment: '
                        '{marker}'.format(**locals())
                    )
                    self._plan['waiting'].remove(marker)
                    self._plan['in-progress'].add(marker)
                    for host, manifest in manifests:
                        run = greenlet.greenlet(self._drones[host].deploy)
                        runners.setdefault(marker, set()).add(run)
                        run.switch(manifest, timeout=timeout, debug=debug)
                wait_for_runners(runners[marker])
                # check marker deployment end
                if not runners[marker]:
                    self._plan['finished'].add(marker)
                    self._plan['in-progress'].remove(marker)
        self._callbacks['status']('phase', 'deployment', 'end')

    def run_cleanup(self):
        """Completely cleans deploy hosts

        As first 'clean' phase is executed. At the end all temporary
        directories are deleted.
        """
        self._callbacks['status']('phase', 'cleanup', 'start')
        self.run_phase('clean')
        for drone in self._drones.values():
            drone.clean()
        self._callbacks['status']('phase', 'cleanuo', 'end')

    def register_status_callback(self, callback):
        """Registers callbacks for reporting installation status.

        Callback has to accept parameters: unit_type, unit_name, unit_status.
        Callback can accept parameter 'additional' which contains None or dict
        of additional data depending on unit_type. Parameter unit_type can
        contain values: 'phase', 'step', 'manifest'.
        """
        self._callbacks['status'] = callback
