##########################################################################
# NSAp - Copyright (C) CEA, 2017
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

"""
Plugin authentication retriever
"""

# System import
import os.path as osp
import base64

# CubicWeb import
from cubicweb import AuthenticationError
from cubicweb.server.sources import native
from cubes.schiirdor.ldapfeed import LDAPConnection
from cubes.trustedauth.cryptutils import build_cypher


class SSORetriever(native.BaseAuthentifier):
    """ A source SSO authentifier plugin.
    Login comes encrypted + base64 encoded, we decrypt it with a special key
    to identify the trustfulness of the 'client'
    """
    auth_rql = ("Any X WHERE X is CWUser, X login '{0}'")
    src_rql = ("Any X, T, U, C Where X is CWSource, X name '{0}', "
               "X type T, X url U, X config C")
    src_name = "SCHIIRDOR_SOURCE"

    def authenticate(self, session, login, **authinfo):
        """ Return a CWUser eid for the given login (coming from
        'sso-user-retriever' http headers) if this account is defined in this
        source, else raise 'AuthenticationError'.
        """
        # Message
        session.info("Authentication by %s.", self.__class__.__name__)
        session.debug("Try to identify user '%s'.", login)
        # If the login is not in the CW registration instance
        session.debug("Checking user '%s' is registered in CW.", login)
        with session.repo.internal_cnx() as cnx:
            rset = cnx.execute(self.auth_rql.format(login))
            user_eid = rset[0][0]
        if session.vreg.config.get("check-user-register-in-cw", True):
            if rset.rowcount != 1:
                session.error("User '{0}' not in CubicWeb.".format(login))
                raise AuthenticationError(
                    "User '{0}' not in CubicWeb.".format(login))
        # 2003 Active Directory allows anonymous binds. So not providing a
        # user id at all will still pass a simple bind check, if the only
        # thing being tested is whether simple_bind_s() throws an error.
        # 2003 Active Directory does require authentication for any searches
        # that aren't attributes of the rootDSE.
        session.debug("Tying to access source '%s'.", self.src_name)
        with session.repo.internal_cnx() as cnx:
            rset = cnx.execute(self.src_rql.format(self.src_name))
        if rset.rowcount != 1:
            session.debug("No resource attached to this RQL: {0}.".format(
                self.src_rql.format(self.src_name)))
            raise Exception("No resource attached to this RQL: "
                            "{0}.".format(self.src_rql))
        seid, stype, surl, sconfig = rset[0]
        session.debug("Granting LDAP credentials for user '%s'.", login)
        try:
            # Create a connection to the ldap resource
            cyphr = build_cypher(session.vreg.config._secret)
            ldap_login = cyphr.decrypt(
                base64.decodestring(session.vreg.src_authlogin)).strip()
            ldap_password = cyphr.decrypt(
                base64.decodestring(session.vreg.src_authpassword)).strip()
            connection = LDAPConnection(seid, self.src_name, stype, surl,
                                        sconfig, ldap_login, ldap_password,
                                        verbose=0)
            # Check user credentials
            connection.is_valid_user(login, authinfo["password"])
            connection.close()
            return user_eid
        except Exception, exc:
            session.error("Authentication failure for user '%s' "
                          "[%s]." %(login, exc))
            pass
        raise AuthenticationError("User is not registered.")

