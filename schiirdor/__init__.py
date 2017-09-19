##########################################################################
# NSAp - Copyright (C) CEA, 2017
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System import
from packaging import version

# Cubicweb import
import cubicweb
from logilab.common.decorators import monkeypatch
from logilab.common.decorators import cachedproperty
from cubicweb.sobjects.ldapparser import DataFeedLDAPAdapter
from cubicweb.server.sources.ldapfeed import LDAPFeedSource


"""
TODO 
Fix LDAP synch:
only required in CW > 3.21.
this code must be removed in newest release.
"""


cw_version = version.parse(cubicweb.__version__)
if cw_version >= version.parse("3.21.0"):

    from cubicweb.sobjects.ldapparser import UserMetaGenerator
    from cubicweb.dataimport import stores

    @monkeypatch(DataFeedLDAPAdapter)
    def build_store(self):
        """ Instantiate and configure a store.
        """
        metagenerator = UserMetaGenerator(
            self._cw, source=self.source,
            meta_skipped=("container_parent", "container_etype"))
        return stores.NoHookRQLObjectStore(self._cw, metagenerator)


    @monkeypatch(LDAPFeedSource)
    def _search(self, cnx, base, scope,
                searchstr='(objectClass=*)', attrs=()):
        """make an ldap query"""
        self.debug('ldap search %s %s %s %s %s', self.uri, base, scope,
                   searchstr, list(attrs))
        if self._conn is None:
            self._conn = self._connect()
        ldapcnx = self._conn
        if not ldapcnx.search(base, searchstr, search_scope=scope, attributes=attrs):
            return []
        result = []
        for rec in ldapcnx.response:
            if rec['type'] != 'searchResEntry':
                continue
            items = rec['attributes'].items()
            itemdict = self._process_ldap_item(rec['dn'], items)
            itemdict["dn"] = itemdict["dn"].encode("ascii", "xmlcharrefreplace")
            result.append(itemdict)
        self.debug('ldap built results %s', len(result))
        return result
