# -*- coding: utf-8 -*-

""" Example plugin for tests. This plugin should be able to install
SQL database server.
"""

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import uuid


def length_validator(value, key, config):
    # All three parameters are mandatory. Value to validate, key in config and
    # config itself. Note that values in given config might not be processed
    # or validated, so use config.get_validated(some_key) if you need to read
    # other config value.
    # Validators has to raise ValueError if given value is invalid.
    if len(value) < 8:
        raise ValueError('Password is too short.')


def password_processor(value, key, config):
    # All three parameters are mandatory. Value to validate, key in config and
    # config itself. Note that values in given config might not be processed
    # or validated, so use config.get_validated(some_key) if you need to read
    # other config value.
    # Processors returns processed value which will be corrected in config.
    if not value:
        return uuid.uuid4().hex[:8]
    return value



# List of dicts defining configuration paramaters for plugin
CONFIGURATION = [
    {'name': 'sql/host',
     'usage': 'SQL server hostname / IP address',
     'default': '192.168.1.1'},

    {'name': 'sql/backend',
     'usage': ('Type of SQL server. Possible values are "postgresql" '
               'for PostreSQL server or "mysql" for MySQL / MariaDB server '
               '(depends on host OS platform).'),
     'default': 'mysql',
     'options': ['postgresql', 'mysql']},

    {'name': 'sql/admin_user',
     'usage': 'Admin user name',
     'default': 'admin'},

    {'name': 'sql/admin_password',
     'usage': 'Admin user password',
     'processors': [password_processor],
     'validators': [length_validator]},
]

# List of paths to Puppet modules which are required by this plugin
MODULES = []

# List of paths to Puppet resources
RESOURCES = []

# List of callables (steps) which will run at first even before Puppet
# installation.  Every initialization step will be run for each registred host.
# Step callable has to accept following parameters:
# host - hostname or IP of currently initializing host
# config - kanzo.conf.Config object containing loaded configuration
#          from config file
# messages - list for messages generated by step which can be presented to user
#            in final application
INITIALIZATION = []

# List of callables (steps) which will run right before Puppet is run,
# which means after Puppet installation and initialization. Every preparation
# step will be run for each registred host. Step callable has to accept
# following parameters:
# host - hostname or IP of currently initializing host
# config - kanzo.conf.Config object containing loaded configuration
#          from config file
# info - dict containing single host information
# messages - list for messages generated by step which can be presented to user
#            in final application
PREPARATION = []

# List of callables which will be used to generate puppet manifests
# for deployment. Each callable should return list of generated manifests
# (can be empty if no manifest is generated). List items should be tuples
# containing: (host-to-deploy-on, manifest-name, manifest-marker, prereqs)
# where marker is identifier of manifest and prereqs is list of markers
# on which manifest is dependent on and won't start deploying unless all prereqs
# are successfully deployed. Manifests with the same marker will run paralel
# assuming they are deployed on different hosts.
# Step callable has to accept following  parameters:
# config - kanzo.conf.Config object containing loaded configuration
#          from config file
# info - dict containing hosts information
# messages - list for messages generated by step which can be presented to user
#            in final application
DEPLOYMENT = []

# List of callables (steps) which will run after Puppet is finished with hosts
# configuration. Every initialization step will be run for each registred host.
# Step callable has to accept following parameters:
# host - hostname or IP of currently initializing host
# config - kanzo.conf.Config object containing loaded configuration
#          from config file
# info - dict containing single host information
# messages - list for messages generated by step which can be presented to user
#            in final application
CLEANUP = []
