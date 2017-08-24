##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System import
import collections
import base64
import re
import time
import json
import smtplib
import logging
from email.mime.text import MIMEText

# CubicWeb import
from cubicweb import tags
from cubicweb.view import StartupView
from cubicweb.web.views.tableview import EntityTableView
from cubicweb.web.views.tableview import EntityTableColRenderer
from cubicweb.web.views.tableview import MainEntityColRenderer
from cubicweb.predicates import match_user_groups
from cubicweb.predicates import is_instance
from cubicweb.web.views import add_etype_button
from cubicweb.web.views.ajaxcontroller import ajaxfunc
from cubicweb.web.views.reledit import reledit_form as cw_reledit_form
from cubicweb.web.views.reledit import AutoClickAndEditFormView
from logilab.common.decorators import monkeypatch
from cubicweb import _

# Cubes import
from .predicates import trust_authenticated
from cubes.schiirdor.ldapfeed import LDAPConnection
from cubes.trustedauth.cryptutils import build_cypher


###############################################################################
# Sync button
###############################################################################

class SCHIIRDORSyncManagementView(StartupView):
    """ Synchronize users and groups to the 'SCHIIRDOR_DESTINATION' ldap based
    resource.
    """
    __regid__ = "schiirdor.sync-management"
    __select__ = (StartupView.__select__ &
                  match_user_groups("managers", "moderators"))
    title = _("Synchronize Users & Groups")
    cache_max_age = 0 # disable caching

    rql = ("Any F, S, UAA, L, USN, GN WHERE U is CWUser, "
           "U login L, NOT U login IN ('anon', 'admin'), U in_group G, "
           "NOT G name IN ({0}), G name GN, U firstname F, U surname S, "
           "U in_state US, US name USN, U primary_email UA?, UA address UAA")
    user_rql = ("Any L WHERE U is CWUser, U login L, "
                "NOT U login IN ('anon', 'admin')")
    src_name = "SCHIIRDOR_DESTINATION"
    src_rql = ("Any X, T, U, C Where X is CWSource, X name 'SCHIIRDOR_DESTINATION', "
               "X type T, X url U, X config C")

    user_email_subject = "[SCHIIRDOR] Moderators modified your access rights"
    user_email_body = "Dear %(login)s,\n\n"
    user_email_body += ("The core analysis group moderators modified your "
                        "access rights to the data repository.\n\n")
    user_email_body += "Thank you."
    deactivated_email_body = "Dear %(login)s,\n\n"
    deactivated_email_body += (
        "The core analysis group moderators modified your access rights to "
        "the data repository.\n")
    deactivated_email_body += ("You have no more access rights.\n\n")
    deactivated_email_body += "Thank you."

    admin_email_subject = "[SCHIIRDOR] New moderation action"
    admin_email_body = "'%(login)s' has performed a new moderation action.\n"
    admin_email_body += "Affected users:\n\n"
    admin_email_body += "%(affected_users)s"

    def call(self, **kwargs):
        """ Start synchronisation with destination source: users and associated
        groups.
        """
        # Create a connection to the ldap resource
        cyphr = build_cypher(self._cw.vreg.config._secret)
        login = cyphr.decrypt(
            base64.decodestring(self._cw.vreg.dest_authlogin)).strip()
        password = cyphr.decrypt(
            base64.decodestring(self._cw.vreg.dest_authpassword)).strip()
        with self._cw.session.repo.internal_cnx() as cnx:
            rset = cnx.execute(self.src_rql)
        if rset.rowcount != 1:
            raise Exception("No resource attached to this RQL: "
                            "{0}.".format(self.src_rql))
        seid, stype, surl, sconfig = rset[0]
        if stype != "ldapfeed":
            raise Exception("Source '{0}' must be of 'ldapfeed' "
                            "type.".format(self.src_name))
        connection = LDAPConnection(seid, self.src_name, stype, surl, sconfig,
                                    login, password)

        # Display title
        self.w(u"<h1>{0}</h1>".format(self.title))
        self.w(u"</br>")

        # Get the active group members
        active_grp_name = self._cw.vreg.config.get("active-group", "")
        active_grp = connection.is_valid_group(
            active_grp_name, filter_attributes=True)
        if active_grp is not None:
            active_members = active_grp.get("members", [])
            if not isinstance(active_members, list):
                active_members = [active_members]
        else:
            active_members = None
        self._cw.session.info("Active members in '{0}': {1}.".format(
            active_grp_name, active_members))

        # Synchronize managed users with destination source.
        # TODO: use instance reject groups to format RQL
        restricted_groups = (
            self._cw.vreg.config.get("restricted-groups", []) +
            [self._cw.vreg.config.get("active-group", "")])

        rset = self._cw.execute(
            self.rql.format(json.dumps(restricted_groups)[1: -1]))
        errors = []
        syncs = {}
        users = {}
        activated = []
        active_users = set()
        cw_user_group_map = {}
        for firstname, surname, mail, login, status, group in rset.rows:
            if status == "activated":

                # Record active users: user at least in one group
                active_users.add(login)

                # Record all user associated groups
                cw_user_group_map.setdefault(group, []).append(login)

                # Create/get the group
                grp = connection.is_valid_group(group, filter_attributes=True)
                if grp is None:
                    self._cw.session.info("Create user '%s'." % login)
                    connection.create_group(group)
                    grp = connection.is_valid_group(group,
                                                    filter_attributes=True)

                # Get the group members
                members = grp.get("members", [])
                if not isinstance(members, list):
                    members = [members]

                # Create/get the user
                user = connection.is_valid_login(login)
                # TODO: use a valid password
                if user is None:
                    self._cw.session.info("Create group '%s'." % group)
                    secret = cyphr.encrypt("%128s" % login)
                    connection.create_user(login, secret, firstname,
                                           surname)

                # Update the group members if necessary
                if login not in members:
                    self._cw.session.info(
                        "Add user '%s' in group '%s'." % (login, group))
                    connection.add_user_in_group(group, login)
                    syncs.setdefault(login, []).append(group)
                else:
                    users.setdefault(login, []).append(group)

                # Add this user to the active group if requested
                if active_members is not None:
                    if login not in active_members:
                        self._cw.session.info("Activate user '%s'." % login)
                        connection.add_user_in_group(active_grp_name, login)
                        activated.append(login)
                    active_members.append(login)
                    cw_user_group_map.setdefault(active_grp_name, []).append(
                        login)

            else:
                self._cw.session.error("User '%s' is in quarantine." % login)
                errors.append(login)

        # Remove unecessary user/group relation in destination source
        groups, users_info = connection.dump_users_and_groups()
        emails = {}
        for item in users_info:
            if "mail" in item:
                emails[item["login"]] = item["mail"]
        removed = {}
        deactivated = []
        for group_struct in groups:
            grpname = group_struct["name"]
            grpmembers = group_struct.get("members", [])
            if not isinstance(grpmembers, list):
                grpmembers = [grpmembers]
            grpmembers = set(grpmembers)
            cw_grpmembers = set(cw_user_group_map.get(grpname, []))
            for login in (grpmembers - cw_grpmembers):
                self._cw.session.info(
                    "Remove user '%s' in group '%s'." % (login, grpname))
                connection.remove_user_from_group(grpname, login)
                if grpname == active_grp_name:
                    deactivated.append(login)
                else:
                    removed.setdefault(login, []).append(grpname)

        # Close connection
        connection.close()


        # Save actions to log file
        logger = logging.getLogger("schiirdor.moderation")
        admin_reprot = {
            "syncs": syncs,
            "removed": removed,
            "activated": activated,
            "deactivated": deactivated,
            "quarantine": errors}
        tic = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        message = "[{0}] {1}".format(self._cw.session.login,
                                     json.dumps(admin_reprot))
        logger.info(message)

        # Send notification email
        for login in syncs:
            if login not in emails:
                self._cw.session.error("'%s' has no registered email." % login)
                continue
            self.sendmail(sender_email=self._cw.vreg.config["sender-addr"],
                          recipients_list=[emails[login]],
                          subject=self.user_email_subject,
                          body=self.user_email_body % {"login": login},
                          smtp_host=self._cw.vreg.config["smtp-host"],
                          smtp_port=self._cw.vreg.config["smtp-port"])
        for login in deactivated:
            if login not in emails:
                self._cw.session.error("'%s' has no registered email." % login)
                continue
            self.sendmail(sender_email=self._cw.vreg.config["sender-addr"],
                          recipients_list=[emails[login]],
                          subject=self.user_email_subject,
                          body=self.deactivated_email_body % {"login": login},
                          smtp_host=self._cw.vreg.config["smtp-host"],
                          smtp_port=self._cw.vreg.config["smtp-port"])
        self.sendmail(
            sender_email=self._cw.vreg.config["sender-addr"],
            recipients_list=self._cw.vreg.config["administrator-emails"],
            subject=self.admin_email_subject,
            body=self.admin_email_body % {
                "affected_users": json.dumps(admin_reprot, indent=4,
                                             sort_keys=True),
                "login": self._cw.session.login},
            smtp_host=self._cw.vreg.config["smtp-host"],
            smtp_port=self._cw.vreg.config["smtp-port"])

        # Display goodbye message
        if len(errors) == 0:
            errors.append("No user")
        self.w(u"<h3>Applied rights modifications</h3>")
        self.w(unicode(
            self.summary_table(syncs, removed, activated,deactivated)))
        self.w(u"<h3>Current rights</h3>")
        self.w(unicode(self.rights_summary_table(users)))
        self.w(u"<h3>Blocked users</h3>")
        self.w(u"{0}".format("-".join(errors)))

    def rights_summary_table(self, users):
        """ Create a rights summary table.
        """
        logins = sorted(users.keys())
        html = '<table class="table table-striped">'
        html += '<thead>'
        html += '<tr>'
        html += '<th>Login</th>'
        html += '<th>In groups</th>'
        html += '</tr>'
        html += '</thead>'
        html += '<tbody>'
        if len(logins) > 0:
            for item in logins:
                html += '<tr>'
                html += '<td>{0}</td>'.format(item)
                html += '<td>{0}</td>'.format(" - ".join(users[item]))
                html += '</tr>'
        else:
            html += '<tr>'
            html += '<td>no modification</td>'
            html += '<td></td>' * 2
            html += '</tr>'
        html += '</tbody>'
        html += '</table>'
        return html

    def summary_table(self, syncs, removed, activated, deactivated):
        """ Create a summary table.
        """
        logins = sorted(set(syncs.keys() + removed.keys()))
        html = '<table class="table table-striped">'
        html += '<thead>'
        html += '<tr>'
        html += '<th>Login</th>'
        html += '<th>Activate</th>'
        html += '<th>Deactivate</th>'
        html += '<th>Add in groups</th>'
        html += '<th>Remove from groups</th>'
        html += '</tr>'
        html += '</thead>'
        html += '<tbody>'
        if len(logins) > 0:
            for item in logins:
                html += '<tr>'
                html += '<td>{0}</td>'.format(item)
                html += '<td>{0}</td>'.format(
                    "yes" if item in activated else "")
                html += '<td>{0}</td>'.format(
                    "yes" if item in deactivated else "")
                html += '<td>{0}</td>'.format(
                    " - ".join(syncs[item]) if item in syncs else "")
                html += '<td>{0}</td>'.format(
                    " - ".join(removed[item]) if item in removed else "")
                html += '</tr>'
        else:
            html += '<tr>'
            html += '<td>no data</td>'
            html += '<td></td>' * 4
            html += '</tr>'
        html += '</tbody>'
        html += '</table>'
        return html

    def sendmail(self, sender_email, recipients_list, subject,
                 body, smtp_host, smtp_port):
        """ Sends an email.

        Parameters
        ----------
        sender_email: string (mandatory)
            The sender email address.
        recipients_list: list of str (mandatory)
            List of the recipients emails addresses.
        subject: string (mandatory)
            The email subject.
        body: string (mandatory)
            The email body.
        smtp_host: string (mandatory)
            The SMTP server address.
        smtp_port: int (mandatory)
            The SMTP server port.
        """
        msg = MIMEText(body)
        msg['Subject'] = "{0}".format(subject)
        msg['To'] = ", ".join(recipients_list)
        s = smtplib.SMTP(smtp_host, smtp_port)
        s.sendmail(sender_email, recipients_list, msg.as_string())
        s.quit()



###############################################################################
# Groups button
###############################################################################

class SCHIIRDORUserManagementView(StartupView):
    """ Manage user associated groups.
    """
    __regid__ = "schiirdor.users-management"
    __select__ = (StartupView.__select__ &
                  match_user_groups("managers", "moderators"))
    title = _("Manage User associated Groups")
    cache_max_age = 0 # disable caching
    rql = ("Any U,US,F,S,U,UAA,UDS, L,UAA,USN,UDSN ORDERBY L WHERE "
           "U is CWUser, U login L, NOT U login IN ('anon', 'admin'), "
           "U firstname F, U surname S, U in_state US, US name USN, "
           "U primary_email UA?, UA address UAA, "
           "U cw_source UDS, US name UDSN")

    def call(self, **kwargs):
        self.w(u"<h1>{0}</h1>".format(self.title))
        rset = self._cw.execute(self.rql)
        if rset.rowcount > 0:
            self.wview("schiirdor.users-table", rset)
        else:
            self.w(u"No user to manage.".format(self.title))


@monkeypatch(AutoClickAndEditFormView)
def _compute_formid_value(self, rschema, role, rvid, formid):
    """  Filter the user associed groups that will be displayed in the edit
    view.
    """
    with self._cw.session.repo.internal_cnx() as cnx:
        if (self.entity.__class__.__name__ == "CWUser" and rschema == "in_group"
                and "managers" not in [grp.name for grp in self._cw.user.in_group]):
            restriction = tuple(
                self._cw.vreg.config["restricted-groups"] +
                [self._cw.vreg.config["active-group"]])
            related_rset = cnx.execute(
                "Any G Where U eid '{0}', U in_group G, NOT G name IN "
                "{1}".format(self.entity.eid, repr(restriction)))
        else:
            related_rset = self.entity.related(rschema.type, role)
        if related_rset:
            value = self._cw.view(rvid, related_rset)
        else:
            value = self._compute_default_value(rschema, role)
        if not self._should_edit_relation(rschema, role):
            return None, value
        return formid, value


@ajaxfunc(output_type="xhtml")
def reledit_form(self):
    """ Filter the groups that will be displayed in the edit view.
    """
    req = self._cw
    args = dict((x, req.form[x])
                for x in ('formid', 'rtype', 'role', 'reload', 'action'))
    rset = req.eid_rset(int(self._cw.form['eid']))
    try:
        args['reload'] = json.loads(args['reload'])
    except ValueError: # not true/false, an absolute url
        assert args['reload'].startswith('http')
    view = req.vreg['views'].select('reledit', req, rset=rset, rtype=args['rtype'])

    html = self._call_view(view, **args)
    if "managers" not in [grp.name for grp in self._cw.user.in_group]:
        for name in (req.vreg.config["restricted-groups"] +
                [self._cw.vreg.config["active-group"]]):
            regex = '<option value="[0-9]*">{1}.*</option>'.format(
                self._cw.form['eid'], name)
            html = re.sub(regex, "", html)

    return html


class SCHIIRDORUsersTable(EntityTableView):
    """ Display a table with the user information to be managed.
    """
    __regid__ = "schiirdor.users-table"
    __select__ = (is_instance("CWUser") &
                  match_user_groups("managers", "moderators"))
    columns = ["user", "in_state", "firstname", "surname",
               "in_group", "primary_email", "cw_source"]
    finalvid = "editable-final"

    column_renderers = {
        "user": EntityTableColRenderer(
            renderfunc=lambda w,x: w(x.login),
            sortfunc=lambda x: x.login),
        "in_state": EntityTableColRenderer(
            renderfunc=lambda w,x: w(
                x.cw_adapt_to("IWorkflowable").printable_state),
            sortfunc=lambda x: x.cw_adapt_to(
                "IWorkflowable").printable_state),
        "in_group": EntityTableColRenderer(
            renderfunc=lambda w,x: x.view(
                "reledit", rtype="in_group", role="subject", w=w)),
        "primary_email": EntityTableColRenderer(
            renderfunc=lambda w,x: w(x.primary_email and x.primary_email[0].display_address() or u""),
            sortfunc=lambda x: x.primary_email and x.primary_email[0].display_address() or u""),
        "cw_source": EntityTableColRenderer(
            renderfunc=lambda w,x: w(x.cw_source[0].name),
            sortfunc=lambda x: x.cw_source[0].name)
    }


###############################################################################
# Import users&groups button
###############################################################################

class SCHIIRDORImportView(StartupView):
    """ Import users and groups from the 'SCHIIRDOR_DESTINATION' ldap resource.

    This mechanism can be used as a backup system in case the database is
    corrupted.
    """
    __regid__ = "shiirdor.users-groups-import"
    title = _("Import Users&Groups")
    __select__ = StartupView.__select__ & match_user_groups("managers")
    cache_max_age = 0 # disable caching
    src_name = "SCHIIRDOR_DESTINATION"
    src_rql = ("Any X, T, U, C Where X is CWSource, X name 'SCHIIRDOR_DESTINATION', "
               "X type T, X url U, X config C")

    def call(self, **kwargs):
        # Display a title
        self.w(u"<h1>{0}</h1>".format(self.title))

        # Create a connection to the ldap resource
        cyphr = build_cypher(self._cw.vreg.config._secret)
        login = cyphr.decrypt(
            base64.decodestring(self._cw.vreg.dest_authlogin)).strip()
        password = cyphr.decrypt(
            base64.decodestring(self._cw.vreg.dest_authpassword)).strip()
        with self._cw.session.repo.internal_cnx() as cnx:
            rset = cnx.execute(self.src_rql)
        if rset.rowcount != 1:
            raise Exception("No resource attached to this RQL: "
                            "{0}.".format(self.src_rql))
        seid, stype, surl, sconfig = rset[0]
        if stype != "ldapfeed":
            raise Exception("Source '{0}' must be of 'ldapfeed' "
                            "type.".format(self.src_name))
        connection = LDAPConnection(seid, self.src_name, stype, surl, sconfig,
                                    login, password, verbose=0)

        # Create missing users and groups entities and associated relations via
        # the 'in-group' relation.
        groups_data, users_data = connection.dump_users_and_groups()
        allowed_logins = []
        allowed_groups = {}
        self.w(u"<ul>")
        with self._cw.session.repo.internal_cnx() as cnx:

            # create new users
            for user_info in users_data:
                req = "Any X WHERE X is CWUser, X login '{0}'".format(
                    user_info["login"])
                allowed_logins.append(user_info["login"])
                rset = cnx.execute(req)
                if rset.rowcount == 0:
                    self.w(u"<li>[info] creating user '{0}'...</li>".format(
                        user_info["login"]))
                    req = "INSERT CWUser X, EmailAddress Y: "
                    have_email = False
                    for attribute, value in user_info.items():
                        if "mail" in attribute.lower():
                            if not have_email:
                                req += " X primary_email Y, Y address '%(value)s'," % {"value": value}
                                have_email = True
                        else:
                            req += " X %(attribute)s '%(value)s'," % {
                                "attribute": attribute, "value": value}
                    req += "X in_group G WHERE G name 'users'"
                    print req
                    rset = cnx.execute(req)

            # create new groups
            for group_info in groups_data:
                grpname = group_info["name"]
                req = "Any X WHERE X is CWGroup, X name '{0}'".format(grpname)
                rset = cnx.execute(req)
                if rset.rowcount == 0:
                    self.w(u"<li>[info] creating group '{0}'...</li>".format(
                        grpname))
                    req = "INSERT CWGroup X: X name '{0}'".format(grpname)
                    rset = cnx.execute(req)

                # link group associated users
                members = group_info.get("members", [])
                if not isinstance(members, list):
                    members = [members]
                for login in members:
                    if login not in allowed_logins:
                        self.w(u"<li>[warn] unexpected user '{0}' in group "
                                "'{1}'.</li>".format(login, grpname))
                        continue
                    allowed_groups.setdefault(login, []).append(grpname)
                    req = ("Any X WHERE X is CWUser, X login '{0}', "
                           "X in_group G, G name '{1}'".format(login, grpname))
                    rset = cnx.execute(req)
                    if rset.rowcount == 0:
                        self.w(u"<li>[info] adding relation '{0}' in_group "
                                "'{1}'...</li>".format(login, grpname))
                        req = ("SET X in_group G WHERE X is CWUser, "
                               "X login '{0}', G is CWGroup, "
                               "G name '{1}'".format(login, grpname))
                        rset = cnx.execute(req)
            cnx.commit()

        # Delete extra users and groups.
        with self._cw.session.repo.internal_cnx() as cnx:

            # get all CW users
            users = set([
                row[0]
                for row in cnx.execute("Any L WHERE X is CWUser, X login L")])
            users -= {"admin"}

            # delete unknown users
            for login in users:
                if login not in allowed_logins:
                    self.w(u"<li>[info] removing user '{0}'...</li>".format(
                        login))
                    req = "DELETE CWUser X Where X login '{0}'".format(login)
                    rset = cnx.execute(req)

                # delete user associated groups
                req = ("Any N WHERE X is CWUser, X login '{0}', X in_group G, "
                       "G name N".format(login))
                groups = set([row[0]for row in cnx.execute(req)])
                groups -= set(self._cw.vreg.config["restricted-groups"])
                for grpname in groups:
                    if grpname not in allowed_groups.get(login, []):
                        self.w(u"<li>[info] removing group '{0}'..."
                                "</li>".format(grpname))
                        req = "DELETE CWGroup X Where X name '{0}'".format(
                            grpname)
                        rset = cnx.execute(req)
            cnx.commit()

        # Close ldap connection
        connection.close()

        # Goodbye message
        self.w(u"<li>done.</li>")
        self.w(u"</ul>")


###############################################################################
# Create groups button
###############################################################################

class SCHIIRDORGroupsManagementView(StartupView):
    """ Manage groups.
    """
    __regid__ = "shiirdor.groups-management"
    title = _("Manage Groups")
    __select__ = StartupView.__select__ & match_user_groups("managers")
    cache_max_age = 0 # disable caching
    rql = ("Any G,GN ORDERBY GN WHERE G is CWGroup, G name GN, NOT G "
           "name 'owners'")

    def call(self, **kwargs):
        self.w(u"<h1>{0}</h1>".format(self.title))
        self.w(add_etype_button(self._cw, "CWGroup"))
        self.w(u"<div class='clear'></div>")
        self.wview('shiirdor.groups-table', self._cw.execute(self.rql))


class SCHIIRDORGroupsTable(EntityTableView):
    """ Display a table with the groups information to be managed.
    """
    __regid__ = "shiirdor.groups-table"
    __select__ = is_instance("CWGroup") & match_user_groups("managers")
    columns = ["group", "nb_users"]

    column_renderers = {
        "group": MainEntityColRenderer(),
        "nb_users": EntityTableColRenderer(
            header=_('num. users'),
            renderfunc=lambda w,x: w(unicode(x.num_users())),
            sortfunc=lambda x: x.num_users()),
    }


###############################################################################
# Create users hidden button
###############################################################################

class SCHIIRDORAdminUsersManagementView(StartupView):
    """ Manage users.
    """
    __regid__ = "shiirdor.admin-users-management"
    title = _("Manage Users")
    __select__ = StartupView.__select__ & match_user_groups("managers")
    cache_max_age = 0 # disable caching
    rql = ("Any U,UL ORDERBY UL WHERE U is CWUser, U login UL, NOT U "
           "login 'admin'")

    def call(self, **kwargs):
        self.w(u"<h1>{0}</h1>".format(self.title))
        self.w(add_etype_button(self._cw, "CWUser"))
        self.w(u"<div class='clear'></div>")
        self.wview('shiirdor.admin-users-table', self._cw.execute(self.rql))


class SCHIIRDORAdminUsersTable(EntityTableView):
    """ Display a table with the users information to be managed.
    """
    __regid__ = "shiirdor.admin-users-table"
    __select__ = is_instance("CWUser") & match_user_groups("managers")
    columns = ["user"]

    column_renderers = {
        "user": MainEntityColRenderer(),
    }


###############################################################################
# Update registry
###############################################################################

def registration_callback(vreg):

    for klass in [SCHIIRDORSyncManagementView, SCHIIRDORUserManagementView,
                  SCHIIRDORUsersTable, SCHIIRDORGroupsManagementView,
                  SCHIIRDORImportView, SCHIIRDORGroupsTable,
                  SCHIIRDORAdminUsersManagementView, SCHIIRDORAdminUsersTable]:
        vreg.register(klass)
    vreg.register_and_replace(reledit_form, cw_reledit_form)
