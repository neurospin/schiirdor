##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System import
import base64

# CubicWeb import
from cubicweb import AuthenticationError
from cubicweb.web.views import authentication, actions, basecontrollers
from cubicweb.web.views.authentication import LoginPasswordRetriever

# Cubes import
from cubes.trustedauth.cryptutils import build_cypher


class SSOUserRetriever(authentication.WebAuthInfoRetreiver):
    """ Single sign-on (SSO) access control of multiple related, but
    independent software systems. With this property a user logs in with a
    single ID and password to gain access to a connected system or systems
    without using different usernames or passwords. The credentials are
    checked in the 'SCHIIRDOR_SOURCE' ldap based resource. All the logged
    users will have a 'trusted_cwuser' attribute attached to their sessions.

    Special login: 'admin' that is directly authentificated by the CubicWeb
    authentification system.
    Special group: 'moderators' that won't have the 'trusted_cwuser' attribute.
    """
    __regid__ = "sso-user-retriever"
    order = 0
    trusted_rql = ("Any X WHERE X is CWUser, X login %(login)s, "
                   "X in_group G, G name 'moderators'")

    def authentication_information(self, req):
        """ Retrieve authentication information from the given request, raise
        NoAuthInfo if expected information is not found.

        Return login and password with secret crypted shared key in the case
        of sso authentification.
        """
        self.info("Web authenticator building auth info.")
        login, password = req.get_authorization()
        if not login:
            raise authentication.NoAuthInfo()
        cyphr = build_cypher(self._cw.config._secret)
        if login != "admin":
            secret = base64.encodestring(cyphr.encrypt("%128s" % login))
            return login, {"password": password, "secret": secret}
        else:
            return login, {"password": password}

    def authenticated(self, retriever, req, session, login, authinfo):
        """ Callback when return authentication information have opened a
        repository connection successfully.
        """
        # Add a flag for remote user
        self.info("Web authenticator running post authentication callback.")
        # Nothing to do for admin login
        if login == "admin":
            return
        with session.repo.internal_cnx() as cnx:
            rset = cnx.execute(self.trusted_rql, {"login": login})
        if rset.rowcount == 0:
            if "secret" not in authinfo:
                raise AuthenticationError(
                    "At this stage expect SSO user only.")
            setattr(session, "trusted_cwuser", True)

    def request_has_auth_info(self, req):
        return req.get_authorization()[0] is not None

    def revalidate_login(self, req):
        return req.get_authorization()[0]


def registration_callback(vreg):
    vreg.register(SSOUserRetriever)
    #vreg.unregister(LoginPasswordRetriever)
