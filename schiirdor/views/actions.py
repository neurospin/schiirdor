##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System imports
import sys
import os
import inspect

# Cubicweb import
from cubicweb.web.views.basetemplates import HTMLPageFooter
from cubicweb.web.views.basetemplates import HTMLPageHeader
from cubicweb.web.views.basetemplates import TheMainTemplate
from cubicweb.web.views.wdoc import HelpAction
from cubicweb.web.views.wdoc import AboutAction
from cubicweb.web.views.actions import PoweredByAction
from cubicweb.web.views.basecomponents import ApplLogo
from logilab.common.decorators import monkeypatch

# Reverse monkey patching of TheMainTemplate done by squareui
# -> 1st step: import TheMainTemplate outside of the current namespace
basetemplates_path = inspect.getfile(TheMainTemplate)
cw_views_dir = os.path.dirname(basetemplates_path)
sys.path.append(cw_views_dir)
from basetemplates import TheMainTemplate as orig


###############################################################################
# ACTIONS
###############################################################################

# Reverse monkey patching of TheMainTemplate done by squareui
# -> 2nd step: reverse the current MainTemplate class methods to the originals.
targets = ["call", "template_header", "template_html_header",
           "template_footer", "nav_column", "content_header", "content_footer"]
for item in targets:
    setattr(TheMainTemplate, item, getattr(orig, item).__func__)


@monkeypatch(TheMainTemplate)
def template_body_header(self, view):
    w = self.w
    w(u'<body>\n')
    w(u'<div id="wrapper">')
    w(u'<div class="overlay"></div>')
    self.wview('header', rset=self.cw_rset, view=view)
    w(u'<div id="page-content-wrapper">')
    w(u'<button type="button" class="hamburger is-closed animated '
        'fadeInLeft" data-toggle="offcanvas">')
    w(u'<span class="hamb-top"></span>')
    w(u'<span class="hamb-middle"></span>')
    w(u'<span class="hamb-bottom"></span>')
    w(u'</button>')
    w(u'<div id="page"><table width="100%" border="0" id="mainLayout"><tr>\n')
    self.nav_column(view, 'left')
    w(u'<td id="contentColumn">\n')
    components = self._cw.vreg['components']
    rqlcomp = components.select_or_none('rqlinput', self._cw, rset=self.cw_rset)
    rqlcomp.formdef = rqlcomp.formdef.replace("%(css_class)s", "schiirdor-search")
    if rqlcomp and self._cw.user.matching_groups("managers"):
        self._cw.add_onload('$(".hamburger").css("top", "40px");')
        rqlcomp.render(w=self.w, view=view)
    msgcomp = components.select_or_none('applmessages', self._cw, rset=self.cw_rset)
    if msgcomp:
        msgcomp.render(w=self.w)
    self.content_header(view)
    w(u'</div>')
    w(u'</div>')


class SchiirdorPageFooter(HTMLPageFooter):
    __regid__ = "footer"
    title = u"Footer"

    def footer_content(self):
        template = self._cw.vreg.template_env.get_template("footer.jinja2")
        html = template.render(
            contact_email=self._cw.vreg.config.get(
                "administrator-emails", "noreply@cea.fr"))
        self.w(html)


class SchiirdorPageHeader(HTMLPageHeader):
    __regid__ = "header"
    title = u"Header"

    def main_header(self, view):
        """ build the top menu with authentification info and the rql box.
        """
        icons = []
        for colid, context in self.headers:
            components = self._cw.vreg["ctxcomponents"].poss_visible_objects(
                self._cw, rset=self.cw_rset, view=view, context=context)
            for comp in components:
                if hasattr(comp, "attributes"):
                    icons.append(comp.attributes())

        # Format template
        template = self._cw.vreg.template_env.get_template("header.jinja2")
        html = template.render(
            anonymous_session=self._cw.session.anonymous_session,
            icons=icons,
            home_url=self._cw.base_url(),
            logout_url=self._cw.build_url("login"))
        self.w(html)


def registration_callback(vreg):

    # Update the footer
    vreg.register_and_replace(SchiirdorPageFooter, HTMLPageFooter)
    vreg.register_and_replace(SchiirdorPageHeader, HTMLPageHeader)
    vreg.unregister(HelpAction)
    vreg.unregister(AboutAction)
    vreg.unregister(PoweredByAction)
    vreg.unregister(ApplLogo)
