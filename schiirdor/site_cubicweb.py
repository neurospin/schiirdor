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
      'default': u'',
      'help': 'seed used to cypher registration data in confirmation email link',
      'group': 'schiirdor',
      'level': 1,
      }),
    ('logo',
     {'type': 'string',
      'default': 'images/nsap.png',
      'help': 'Navigation bar logo',
      'group': 'schiirdor',
      'level': 2,
      }),
    ('disable-ldapfeed',
     {'type' : 'yn',
      'default': True,
      'help': 'If true disable the CubicWeb LDAPFEED connection.',
      'group': 'schiirdor',
      'level': 3,
      }),
    ('check-user-register-in-cw',
     {'type' : 'yn',
      'default': True,
      'help': 'If true user must be registered in CubicWeb to be able to '
              'connect the service, otherwise trust the source only.',
      'group': 'schiirdor',
      'level': 4,
      }),
    ('active-group',
     {'type' : 'string',
      'default': u'',
      'help': 'A group name used to put new user in quarantine. If specified, '
              'users will be automatically added to this group when '
              'moderators grant them access permissions.',
      'group': 'schiirdor',
      'level': 5,
      }),
    ('restricted-groups',
     {'type' : 'csv',
      'default': 'managers,users,guests,owners,moderators',
      'help': 'A list of groups the moderators cannot administrate.',
      'group': 'schiirdor',
      'level': 6,
      })
)
