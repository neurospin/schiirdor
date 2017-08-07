##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

options = (
    ('registration-cypher-seed',
     {'type' : 'string',
      'help': 'a secret file containing a  32 bytes seed used to cypher '
              'confidential data.',
      'group': 'schiirdor',
      'level': 1,
      }),
    ('logo',
     {'type': 'string',
      'default': 'images/nsap.png',
      'help': 'file with the navigation bar logo.',
      'group': 'schiirdor',
      'level': 2,
      }),
    ('disable-ldapfeed',
     {'type' : 'yn',
      'default': True,
      'help': 'if true disable the CubicWeb LDAPFEED connection.',
      'group': 'schiirdor',
      'level': 3,
      }),
    ('check-user-register-in-cw',
     {'type' : 'yn',
      'default': True,
      'help': 'if true user must be registered in CubicWeb in order to be '
              'able to connect the service, otherwise trust the source only.',
      'group': 'schiirdor',
      'level': 4,
      }),
    ('active-group',
     {'type' : 'string',
      'default': u'',
      'help': 'a group name used to put new user in quarantine. If specified, '
              'users will be automatically added to this group when '
              'moderators grant them access permissions. They will also be '
              'removed from this group automatically if the user have no more '
              'rights on the system.',
      'group': 'schiirdor',
      'level': 5,
      }),
    ('restricted-groups',
     {'type' : 'csv',
      'default': 'managers,users,guests,owners,moderators',
      'help': 'a list of groups the moderators cannot administrate '
              '(will not see in the modeartion list).',
      'group': 'schiirdor',
      'level': 6,
      }),
    ('source-config',
     {'type' : 'string',
      'help': 'a JSON file containing the AD/LDAP source description. The '
              'content of this fil is examplify in the '
              'migration/update_sources module.',
      'group': 'schiirdor',
      'level': 7,
      }),
    ('destination-config',
     {'type' : 'string',
      'help': 'a JSON file containing the AD/LDAP source description. The '
              'content of this fil is examplify in the '
              'migration/update_sources module.',
      'group': 'schiirdor',
      'level': 8,
      }),
    ('moderation-log',
     {'type' : 'string',
      'help': 'the path to a file where modertion actions will be logged.',
      'group': 'schiirdor',
      'level': 9,
      }),
    ('administrator-emails',
     {'type' : 'csv',
      'default': '',
      'help': 'a list of emails that will be notified when a modeartion '
              'action is performed on the system.',
      'group': 'schiirdor',
      'level': 10,
      })
)
