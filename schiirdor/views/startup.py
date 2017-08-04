##########################################################################
# NSAp - Copyright (C) CEA, 2013
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# Cubicweb import
from cubicweb.web.views.startup import IndexView
from cubicweb import _
from cubicweb.web.views.basecontrollers import LogoutController


class SCHIIRDORIndexView(IndexView):
    """ Class that defines the index view.
    """
    title = _("Index")

    def call(self, **kwargs):
        """ Create the 'index' like page of our site that propose a
        registration form.
        """
        href = self._cw.build_url(
            "login", __message=u"Please login with you account.") 
        self.w(u"<h1>Welcome to the management system</h1>")
        self.w(u"<p>Only moderators have the permission to edit user "
                "permissions and must <a type='button' href='{0}' "
                "class='btn btn-success'>Log in</a> to see the moderation "
                "options in the navigation bar.</p>".format(href))
        self.w(u"<p>If no modearation options are displayed and you think you "
                "have the rights to moderate users, please contact the system "
                "administrator.</p>".format(href))


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
