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


class SCHIIRDORNotModeratorIndexView(IndexView):
    """ Class that defines the index view.
    """
    __regid__ = "index"
    __select__ = authenticated_user() & ~match_user_groups("managers", "moderators")
    title = _("Index")

    def call(self, **kwargs):
        """ Create the loggedin 'index' page of our site.
        """
        # Format template
        template = self._cw.vreg.template_env.get_template("startup.logged.jinja2")
        html = template.render(
            header_url=self._cw.data_url("creative/img/neurospin.jpg"),
            moderator=False)
        self.w(html)


class SCHIIRDORModeratorIndexView(IndexView):
    """ Class that defines the index view.
    """
    __regid__ = "index"
    __select__ = authenticated_user() & match_user_groups("managers", "moderators")
    title = _("Index")

    def call(self, **kwargs):
        """ Create the loggedin 'index' page of our site.
        """
        # Format template
        template = self._cw.vreg.template_env.get_template("startup.logged.jinja2")
        html = template.render(
            header_url=self._cw.data_url("creative/img/neurospin.jpg"),
            moderator=True)
        self.w(html)


class SCHIIRDORIndexView(IndexView):
    """ Class that defines the index view.
    """
    __regid__ = "index"
    __select__ = ~authenticated_user()
    title = _("Index")
    templatable = False

    def call(self, **kwargs):
        """ Create the anonymous 'index' page of our site.
        """
        # Get additional resources links
        css = []
        for path in ("creative/vendor/bootstrap/css/bootstrap.min.css",
                     "creative/vendor/font-awesome/css/font-awesome.min.css",
                     "creative/vendor/magnific-popup/magnific-popup.css",
                     "creative/css/creative.css"):
            css.append(self._cw.data_url(path))
        js = []
        for path in ("creative/vendor/jquery/jquery.min.js",
                     "creative/vendor/bootstrap/js/bootstrap.min.js",
                     "creative/vendor/scrollreveal/scrollreveal.min.js",
                     "creative/vendor/magnific-popup/jquery.magnific-popup.min.js",
                     "creative/js/creative.js"):
            js.append(self._cw.data_url(path))

        # Format template
        template = self._cw.vreg.template_env.get_template("startup.jinja2")
        html = template.render(
            header_url=self._cw.data_url("creative/img/neurospin.jpg"),
            login_url=self._cw.build_url(
                "login", __message=u"Please login with your account."),
            contact_email=self._cw.vreg.config.get(
                "administrator-emails", "noreply@cea.fr"),
            css_url=css,
            js_url=js)
        self.w(html)


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
    vreg.register(SCHIIRDORNotModeratorIndexView)
