##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# CW import
from cubicweb.predicates import match_user_groups
from cubicweb.predicates import anonymous_user
from cubicweb.predicates import authenticated_user
from cubicweb.web.views.boxes import SearchBox
from cubicweb.web.views.bookmark import BookmarksBox
from cubicweb.web.views.basecomponents import HeaderComponent
from cubicweb.web.views.basecomponents import ApplLogo
from cubicweb.web.views.basecomponents import CookieLoginComponent
from logilab.common.decorators import monkeypatch
from cubicweb.web.views.basecomponents import AuthenticatedUserStatus
from cubicweb.web.views.basecomponents import AnonUserStatusLink
from cubicweb.web.views.facets import FilterBox
from cubicweb.web.views.boxes import EditBox
# Cubes import
from cubes.bootstrap.views.basecomponents import BSAuthenticatedUserStatus


try:
    from cubicweb import _
except ImportError:
    _ = unicode


# See actions.py: template_body_header
#SearchBox.__select__ = match_user_groups("managers")


class HomeButton(HeaderComponent):
    """ Build a home button displayed in the header.
    """
    __regid__ = "home-snapview"
    __select__ = authenticated_user()
    order = 0
    context = u"header-right"

    def attributes(self):
        return self._cw.build_url("view", vid="index"), "Home", "fa-home"


class AnonRegisterButton(HeaderComponent):
    """ Build a registration button displayed in the header.
    This button will only be visible if logged as an anonymous user.
    """
    __regid__ = "anon-registration"
    __select__ = anonymous_user()
    context = "header-right"
    order = 1

    def attributes(self):
        return self._cw.build_url("register"), "Register", "fa-sign-up"


class ManagerManageButton(HeaderComponent):
    """ Build a manage button displayed in the header.
    Only administrators and moderators will see this button.
    """
    __regid__ = "manager-manage"
    __select__ = match_user_groups("managers", "moderators") & authenticated_user()
    context = "header-right"
    order = 2

    def attributes(self):
        return (self._cw.build_url("view", vid="schiirdor.users-management"),
                "Users & groups", "fa-users")


class ManagerSyncButton(HeaderComponent):
    """ Build a synchronisation button displayed in the header.
    Only administrators and moderators will see this button.
    """
    __regid__ = "manager-sync"
    __select__ = match_user_groups("managers", "moderators") & authenticated_user()
    context = "header-right"
    order = 3

    def attributes(self):
        return (self._cw.build_url("view", vid="schiirdor.sync-management"),
                "Sync", "fa-exchange")



class AdminGroupButton(HeaderComponent):
    """ Build a create group button displayed in the header.
    Only the managers have accessed to this functionality.
    """
    __regid__ = "admin-status"
    __select__ = match_user_groups("managers") & authenticated_user()
    context = "header-right"
    order = 4

    def attributes(self):
        return (self._cw.build_url("view", vid="shiirdor.groups-management"),
                "Create groups", "fa-plus-square")


class AdminImportButton(HeaderComponent):
    """ Build an importation button displayed in the header.
    Only the managers have accessed to this functionality.
    """
    __regid__ = "admin-import"
    __select__ = match_user_groups("managers") & authenticated_user()
    context = "header-right"
    order = 5

    def attributes(self):
        return (self._cw.build_url("view", vid="shiirdor.users-groups-import"),
                "Import users & groups", "fa-cloud-download")


class LogOutButton(AuthenticatedUserStatus):
    """ Close the current session.
    """
    __regid__ = "logout"
    __select__ = authenticated_user()
    order = 6

    def attributes(self):
        return (self._cw.build_url("logout"), "Sign-out", "fa-sign-out")


@monkeypatch(ApplLogo)
def render(self, w):
    """ Change the logo.
    """
    w(u'<a class="navbar-brand" href="%s"><img id="logo" src="%s" '
      'alt="logo"/></a>' % (
            self._cw.base_url(),
            self._cw.data_url(self._cw.vreg.config.get("logo"))))


def registration_callback(vreg):

    for klass in [AdminGroupButton, ManagerManageButton, LogOutButton,
                  ManagerSyncButton, AdminImportButton, HomeButton]:
        vreg.register(klass)

    for klass in [BookmarksBox, BSAuthenticatedUserStatus,
                  AnonUserStatusLink, FilterBox, EditBox]:
        vreg.unregister(klass)

