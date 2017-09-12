##########################################################################
# NSAp - Copyright (C) CEA, 2017
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# Cubicweb import
from logilab.common.decorators import monkeypatch
from cubicweb.web.views.sessions import InMemoryRepositorySessionManager
from cubicweb.web import DirectResponse
from cubicweb.etwist.http import HTTPResponse
from cubicweb.web import InvalidSession


# Redirection page
anonymous_html = """
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>unauthorized</title>
        <!-- <link rel="stylesheet" href="style.css"> -->
        <!-- <script src="script.js"></script> -->
    </head>
    <body>
        <script>
            alert("%(popup_msg)s");
            window.location.replace("%(redirect_url)s");
        </script>
        <noscript>
            Javascript is not activated.
            Please activate javascript and restart your web-browser.
        </noscript>
    </body>
</html>
"""

# Redirection message
popup_msg = ("Sorry you are not authorized to access this view. If you think "
             "you should, please use the contact mail.")


@monkeypatch(InMemoryRepositorySessionManager)
def get_session(self, req, sessionid):
    """ Return existing session for the given session identifier.
    """
    if sessionid not in self._sessions:
        raise InvalidSession()
    session = self._sessions[sessionid]
    try:
        user = self.authmanager.validate_session(req, session)
    except InvalidSession:
        self.close_session(session)
        raise
    if session.closed:
        self.close_session(session)
        raise InvalidSession()
    if all(group not in session.user.groups
           for group in ["managers", "moderators"]):
        logout_url = req.build_url("logout")
        if req.url() != logout_url:
            parameters = {"popup_msg": popup_msg,
                          "redirect_url": logout_url}
            stream = anonymous_html % parameters
            response = HTTPResponse(code=req.status_out,
                                    headers=req.headers_out,
                                    stream=u'{0}'.format(stream),
                                    twisted_request=req._twreq)
            raise DirectResponse(response)
    return session
