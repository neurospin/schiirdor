##########################################################################
# NSAp - Copyright (C) CEA, 2013
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System import
import os

# Cubicweb import
from cubicweb.web.views.startup import IndexView
from cubicweb.web.views.baseviews import NullView
from cubicweb import _
from cubicweb.web.views.basecontrollers import LogoutController
from cubicweb.predicates import authenticated_user
from cubicweb.predicates import match_user_groups


class SCHIIRDORModeratorIndexView(IndexView):
    """ Class that defines the index view.
    """
    __regid__ = "index"
    __select__ = authenticated_user() and match_user_groups("managers", "moderators")
    title = _("Index")
    default_message = (
        "Your are a modearator of the project. You can assign rights to "
        "users. All actions are registered.")

    def call(self, **kwargs):
        """ Create the 'index' like page of our site that propose a
        registration form.
        """
        self.w(u"<h1>Welecome to the moderation system.</h1>")
        self.w(unicode(self.default_message))


class SCHIIRDORIndexView(IndexView):
    """ Class that defines the index view.
    """
    __regid__ = "index"
    __select__ = ~authenticated_user() or ~match_user_groups("moderators")
    title = _("Index")
    templatable = False
    default_message = "Unable to locate startup page."

    def call(self, **kwargs):
        """ Create the 'index' like page of our site that propose a
        registration form.
        """
        # Get additional resources links
        css = []
        for path in ("creative/vendor/bootstrap/css/bootstrap.min.css",
                     "creative/vendor/font-awesome/css/font-awesome.min.css",
                     "creative/vendor/magnific-popup/magnific-popup.css",
                     "creative/css/creative.css"):
            css.append(
                u'<link rel="stylesheet" type="text/css" href="{0}"/>'.format(
                    self._cw.data_url(path)))
        js = []
        for path in ("creative/vendor/jquery/jquery.min.js",
                     "creative/vendor/bootstrap/js/bootstrap.min.js",
                     "creative/vendor/scrollreveal/scrollreveal.min.js",
                     "creative/vendor/magnific-popup/jquery.magnific-popup.min.js",
                     "creative/js/creative.js"):
            js.append(
                u'<script type="text/javascript" src="{0}"></script>'.format(
                    self._cw.data_url(path)))
        resources = {
            "header-url": self._cw.data_url("creative/img/header.jpg"),
            "login-url": self._cw.build_url(
                "login", __message=u"Please login with your account."),
            "contact-email": unicode(self._cw.vreg.config.get(
                "administrator-emails", "noreply@cea.fr")),
            "css": "\n".join(css),
            "js": "\n".join(js)
        }

        # Get local html startup
        startup_html = os.path.join(os.path.dirname(__file__), "startup.html")
        if os.path.isfile(startup_html):

            with open(startup_html, "rt") as open_file:
                html = open_file.readlines()
            html = "\n".join(html)
            for key, value in resources.items():
                html = html.replace("%({0})s".format(key), value)
            self.w(unicode(html))
        else:
            self.w(unicode(self.default_message))


class SCHIIRDORLogoutController(LogoutController):
    """ redirect properly after logout.
    """
    def goto_url(self):
        """ do NOT redirect to an http:// url """
        msg = self._cw.__("You have been logged out.")
        return self._cw.build_url("view", vid="index", __message=msg)  


def registration_callback(vreg):
    vreg.register_and_replace(SCHIIRDORIndexView, IndexView)
    vreg.register_and_replace(SCHIIRDORLogoutController, LogoutController)
    vreg.register(SCHIIRDORModeratorIndexView)
