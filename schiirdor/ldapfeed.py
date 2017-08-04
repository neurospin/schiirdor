##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System import
import ldap
from ldap.filter import filter_format
from pprint import pprint
import collections

# Cubicweb import
from logilab.common.textutils import text_to_dict
from cubicweb.server.sources.ldapfeed import LDAPFeedSource


# Search scopes
BASE = ldap.SCOPE_BASE
ONELEVEL = ldap.SCOPE_ONELEVEL
SUBTREE = ldap.SCOPE_SUBTREE
LDAP_SCOPES = {"BASE": ldap.SCOPE_BASE,
               "ONELEVEL": ldap.SCOPE_ONELEVEL,
               "SUBTREE": ldap.SCOPE_SUBTREE}


class LDAPConnection(object):
    """ Connection to an Active Directory.
    """

    def __init__(self, seid, sname, stype, surl, sconfig, login, password,
                 verbose=0):
        """ Create a LDAPConnection instance.
        """
        self.config = self.configure(seid, sname, stype, surl, sconfig, login,
                                     password)
        self.verbose = verbose
        self.is_active_directory = (
            self.config["user-login-attr"] == "sAMAccountName")
        if verbose > 0:
            pprint(self.config)
        if self.is_active_directory:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        self.ldapobject = ldap.initialize(self.config["url"])
        self.ldapobject.protocol_version = 3
        if self.is_active_directory:
            self.ldapobject.set_option(ldap.OPT_REFERRALS, 0)
        self.ldapobject.simple_bind_s(self.config["data-cnx-dn"],
                                      self.config["data-cnx-password"])
        self.user_base_filters = [
            filter_format("(%s=%s)", ("objectClass", o))
            for o in self.config["user-classes"]]
        self.group_base_filters = [
            filter_format("(%s=%s)", ("objectClass", o))
            for o in self.config["group-classes"]]
        if verbose > 0:
            pprint(self.user_base_filters)
            pprint(self.group_base_filters)

    @classmethod
    def configure(self, seid, sname, stype, surl, sconfig, login, password):
        """ Update and type the connection configuration.
        """
        if stype != "ldapfeed":
            raise Exception("Source '{0}' must be of 'ldapfeed' "
                            "type.".format(self.sname))
        dictconfig = text_to_dict(sconfig)
        typedconfig = LDAPFeedSource.check_conf_dict(seid, dictconfig)
        typedconfig["url"] = surl
        typedconfig["data-cnx-dn"] = str(typedconfig["data-cnx-dn"].format(
            login))
        typedconfig["data-cnx-password"] = str(password)
        return typedconfig

    def close(self):
        """ Close the connection.
        """
        self.ldapobject.unbind_s()

    def is_valid_user(self, login, password):
        """ Check the user exists in the configured active directory.
        """
        searchstr = filter_format(
            "(%s=%s)", (self.config["user-login-attr"], login))
        if self.verbose > 0:
            pprint(searchstr)
        result = self.ldapobject.search_s(self.config["user-base-dn"],
                                          globals()[self.config["user-scope"]],
                                          searchstr,
                                          None)
        if self.verbose > 0:
            pprint(result)
        user_dn = result[0][0]
        self.ldapobject.simple_bind_s(user_dn, password)

    def is_valid_login(self, login, filter_attributes=False):
        """ Check the login exists in the configured active directory.

        Note:

            The 'attrmap' parameter need to be an ordered dictionary.
        """
        searchfilter = [
            filter_format("(%s=%s)", (self.config["user-login-attr"], login))]
        searchfilter.extend(self.user_base_filters)
        searchstr = "(&%s)" % "".join(searchfilter)
        if self.verbose > 0:
            pprint(searchstr)
        if filter_attributes:
            attrmap = collections.OrderedDict(self.config["user-attrs-map"])
            ldap_attrlist = [
                str(elem) for elem in attrmap.keys()]
            cw_attrlist = attrmap.values()
        else:
            ldap_attrlist = None
            cw_attrlist = []
        result = self.ldapobject.search_s(self.config["user-base-dn"],
                                          globals()[self.config["user-scope"]],
                                          searchstr,
                                          ldap_attrlist)
        if len(result) != 1:
            return None
        elif len(cw_attrlist) == 0:
            return result[0][1]
        else:
            data = {}
            for key, values in result[0][1].items():
                index = ldap_attrlist.index(key)
                if len(values) == 1:
                    values = values[0]
                data[cw_attrlist[index]] = values
            return data

    def is_valid_group(self, group, filter_attributes=False):
        """ Check the group exists in the configured active directory.

        Note:

            The 'attrmap' parameter need to be an ordered dictionary.
        """
        searchfilter = [self.config["group-filter"].format(group)]
        searchfilter.extend(self.group_base_filters)
        searchstr = "(&%s)" % "".join(searchfilter) 
        if self.verbose > 0:
            pprint(searchstr)
        if filter_attributes:
            attrmap = collections.OrderedDict(self.config["group-attrs-map"])
            ldap_attrlist = [
                str(elem) for elem in attrmap.keys()]
            cw_attrlist = attrmap.values()
        else:
            ldap_attrlist = None
            cw_attrlist = []
        result = self.ldapobject.search_s(self.config["group-base-dn"],
                                          globals()[self.config["group-scope"]],
                                          searchstr,
                                          ldap_attrlist)
        if len(result) != 1:
            return None
        elif len(cw_attrlist) == 0:
            return result[0][1]
        else:
            data = {}
            for key, values in result[0][1].items():
                index = ldap_attrlist.index(key)
                if len(values) == 1:
                    values = values[0]
                data[cw_attrlist[index]] = values
            return data

    def create_group(self, group):
        """ Create a group.

        Note:

            No unicity check is performed at this stage.
        """
        groupattr = collections.OrderedDict(self.config["group-attrs-map"])
        group_key = groupattr.keys()[groupattr.values().index("gid")]
        groups_search = self.ldapobject.search_s(
            self.config["group-base-dn"],
            globals()[self.config["group-scope"]],
            "({0}=*)".format(group_key))
        gids = [int(item[1]["gidNumber"][0]) for item in groups_search]
        gid = max(gids) + 1
        groupdn = "cn={0},{1}".format(group, self.config["group-base-dn"])
        attrs = [
            ("objectClass", [str(self.config["group-classes"][0]), "top"]),
            ("cn", [str(group)]),
            (group_key, [str(gid)])
        ]
        if self.verbose > 0:
            pprint(groupdn)
            pprint(attrs)
        return self.ldapobject.add_s(groupdn, attrs)

    def create_user(self, login, crypted_password, firstname, lastname):
        """ Create a user.

        Note:

            No unicity check is performed at this stage.
        """
        cn = str(firstname) + " " + str(lastname)
        userdn = "uid={0},{1}".format(login, self.config["user-base-dn"])
        attrs = [
            ("objectclass", [str(self.config["user-classes"][0])]),
            ("uid", [str(login)]),
            ("cn", [cn]),
            ("sn", [str(lastname)]),
            ("givenName", [str(firstname)]),
            ("userpassword", [str(crypted_password)])
        ]
        if self.verbose > 0:
            pprint(userdn)
            pprint(attrs)
        return self.ldapobject.add_s(userdn, attrs)

    def add_user_in_group(self, group, login):
        """ Add a user to a group.

        Note:

            No unicity check is performed at this stage.
        """
        groupattr = collections.OrderedDict(self.config["group-attrs-map"])
        group_key = groupattr.keys()[groupattr.values().index("members")]
        groupdn = "cn={0},{1}".format(group, self.config["group-base-dn"])
        attrs = [
            (ldap.MOD_ADD, group_key, str(login))
        ]
        if self.verbose > 0:
            pprint(groupdn)
            pprint(attrs)
        return self.ldapobject.modify_s(groupdn, attrs)

    def remove_user_from_group(self, group, login):
        """ Delete a user from a group.

        Note:

            No existence check is performed at this stage.
        """
        groupattr = collections.OrderedDict(self.config["group-attrs-map"])
        group_key = groupattr.keys()[groupattr.values().index("members")]
        groupdn = "cn={0},{1}".format(group, self.config["group-base-dn"])
        attrs = [
            (ldap.MOD_DELETE, str(group_key), str(login))
        ]
        if self.verbose > 0:
            pprint(groupdn)
            pprint(attrs)
        return self.ldapobject.modify_s(groupdn, attrs)

    def dump_users_and_groups(self):
        """ Dump all the users and groups.
        """
        attrmap = collections.OrderedDict(self.config["group-attrs-map"])
        ldap_attrlist = [str(elem) for elem in attrmap.keys()]
        cw_attrlist = attrmap.values()
        groupattr = collections.OrderedDict(self.config["group-attrs-map"])
        group_key = groupattr.keys()[groupattr.values().index("gid")]
        groups_search = self.ldapobject.search_s(
            self.config["group-base-dn"],
            globals()[self.config["group-scope"]],
            "({0}=*)".format(group_key),
            ldap_attrlist)
        if self.verbose > 0:
            pprint(groups_search)
        groups_data = []
        for _, group_info in groups_search:
            data = {}
            for key, values in group_info.items():
                index = ldap_attrlist.index(key)
                if len(values) == 1:
                    values = values[0]
                data[cw_attrlist[index]] = values
            groups_data.append(data)

        attrmap = collections.OrderedDict(self.config["user-attrs-map"])
        ldap_attrlist = [str(elem) for elem in attrmap.keys()]
        cw_attrlist = attrmap.values()
        searchfilter = [
            filter_format("(%s=*)", (self.config["user-login-attr"], ))]
        searchfilter.extend(self.user_base_filters)
        searchstr = "(&%s)" % "".join(searchfilter)
        if self.verbose > 0:
            pprint(searchstr)
        users_search = self.ldapobject.search_s(
            self.config["user-base-dn"],
            globals()[self.config["user-scope"]],
            searchstr,
            ldap_attrlist)
        if self.verbose > 0:
            pprint(users_search)
        users_data = []
        for _, user_info in users_search:
            data = {}
            for key, values in user_info.items():
                index = ldap_attrlist.index(key)
                if len(values) == 1:
                    values = values[0]
                data[cw_attrlist[index]] = values
            users_data.append(data)

        return groups_data, users_data


if __name__ == "__main__":
    config = """
    # Is the repository responsible to automatically import content from this
    # source? You should say yes unless you don't want this behaviour or if you use
    # a multiple repositories setup, in which case you should say yes on one
    # repository, no on others.
    synchronize=no

    # Interval in seconds between synchronization with the external source (default
    # to 5 minutes, must be >= 1 min).
    synchronization-interval=1min

    # Maximum time allowed for a synchronization to be run. Exceeded that time, the
    # synchronization will be considered as having failed and not properly released
    # the lock, hence it won't be considered
    max-lock-lifetime=10min

    # Should already imported entities not found anymore on the external source be
    # deleted?
    delete-entities=no

    # Time before logs from datafeed imports are deleted.
    logs-lifetime=10d

    # Timeout of HTTP GET requests, when synchronizing a source.
    http-timeout=1min

    # authentication mode used to authenticate user to the ldap.
    auth-mode=simple

    # realm to use when using gssapi/kerberos authentication.
    #auth-realm=

    # user dn to use to open data connection to the ldap (eg used to respond to rql
    # queries). Leave empty for anonymous bind
    data-cnx-dn=cn={0},dc=intra,dc=cea,dc=fr

    # password to use to open data connection to the ldap (eg used to respond to
    # rql queries). Leave empty for anonymous bind.
    data-cnx-password=

    # base DN to lookup for users; disable user importation mechanism if unset
    user-base-dn=ou=Users,dc=intra,dc=cea,dc=fr

    # user search scope (valid values: "BASE", "ONELEVEL", "SUBTREE")
    user-scope=SUBTREE

    # classes of user (with Active Directory, you want to say "user" here)
    user-classes=inetOrgPerson

    # additional filters to be set in the ldap query to find valid users
    user-filter=

    # attribute used as login on authentication (with Active Directory, you want to
    # use "sAMAccountName" here)
    user-login-attr=uid

    # name of a group in which ldap users will be by default. You can set multiple
    # groups by separating them by a comma.
    user-default-group=

    # map from ldap user attributes to cubicweb attributes (with Active Directory,
    # you want to use
    # sAMAccountName:login,mail:email,givenName:firstname,sn:surname)
    user-attrs-map=userPassword:upassword,mail:mail,uid:login,givenName:firstname,sn:surname

    # base DN to lookup for groups; disable group importation mechanism if unset
    group-base-dn=ou=Groups,dc=intra,dc=cea,dc=fr

    # group search scope (valid values: "BASE", "ONELEVEL", "SUBTREE")
    group-scope=SUBTREE

    # classes of group
    group-classes=posixGroup

    # additional filters to be set in the ldap query to find valid groups
    group-filter=(cn={0})

    # map from ldap group attributes to cubicweb attributes
    group-attrs-map=memberUid:members,cn:name,gidNumber:gid
    """
    c = LDAPConnection(
        seid=0, sname="SOURCE", stype="ldapfeed",
        surl="ldap://127.0.0.1/", sconfig=config, login="admin",
        password="alpine", verbose=1)
    if 0:
        print c.create_group("group1")
        print c.create_user("user1", "password", "firstname", "lastname")
        print c.add_user_in_group("group1", "user1")
    c.is_valid_user("a", "ab")

