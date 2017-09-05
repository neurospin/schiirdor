##########################################################################
# NSAp - Copyright (C) CEA, 2016
# Distributed under the terms of the CeCILL-B license, as published by
# the CEA-CNRS-INRIA. Refer to the LICENSE file or to
# http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.html
# for details.
##########################################################################

# System import
import getpass
import base64
import os
import json
import logging
import time

# CW import
from cubicweb.server import hook
from cubicweb import ConfigurationError
from cubicweb.predicates import match_user_groups
from cubicweb.server.sources.ldapfeed import LDAPFeedSource

# Cubes import
from cubes.schiirdor.migration.update_sources import _create_or_update_ldap_data_source
from cubes.trustedauth.cryptutils import build_cypher
from cubes.schiirdor.ldapfeed import LDAPConnection
from cubes.schiirdor.authplugin import SSORetriever

# Third party import
from cloghandler import ConcurrentRotatingFileHandler

# Jinja2 import
from jinja2 import Environment
from jinja2 import PackageLoader
from jinja2 import select_autoescape


# Define key entry
KEYCONFENTRY = "registration-cypher-seed"
KEYDISABLEENTRY = "disable-ldapfeed"
KEYINPUTSRC = "source-config"
KEYOUTPUTSRC = "destination-config"


class ConfigureTemplateEnvironment(hook.Hook):
    """ On startup create jinja2 template environment.
    """
    __regid__ = "schiirdor.jinja2-template"
    events = ("server_startup", )

    def __call__(self):
        template_env = Environment(
            loader=PackageLoader("cubes.schiirdor", "templates"),
            autoescape=select_autoescape(["html", "xml"]))
        self.repo.vreg.template_env = template_env


class ServerStartupHook(hook.Hook):
    """ Register SSO authentifier at startup.
    """
    __regid__ = "trustedauth.ssouserinit"
    events = ("server_startup",)

    def __call__(self):
        # XXX use named args and inner functions to avoid referencing globals
        # which may cause reloading pb
        self.debug("Registering SSO authentifier.")
        self.repo.system_source.add_authentifier(SSORetriever())

        # A concurrent log with no rotation keeping no copy
        logfile = self.repo.vreg.config.get("moderation-log")
        if logfile is not None:
            logdir = os.path.dirname(logfile)
        if logfile is not None and os.path.isdir(logdir):
            self.info(
                "Moderation logging will be performed in '{0}'.".format(logfile))
            logger = logging.getLogger("schiirdor.moderation")
            rotateHandler = ConcurrentRotatingFileHandler(
                logfile, "a", maxBytes=0, backupCount=0,)
            logger.addHandler(rotateHandler)
            logger.setLevel(logging.INFO)
            tic = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            logger.info("[START] Service started {0}.".format(tic))
        else:
            self.info("No moderation logging will be performed.")


class InGroupHook(hook.Hook):
    """ Set moderators rights when they administrate groups through the
    'in_group' relation.
    """
    __regid__ = "in-group-hook"
    __select__ = (hook.Hook.__select__ & hook.match_rtype("in_group") &
        ~match_user_groups("managers"))
    events = ("before_add_relation", "before_delete_relation")

    def __call__(self):
        """ Before an 'in_group' relation deletion or addition, check the
        assocaited group name: can't modifiy managers, users, guests and
        moderators group associated unless you are administrator.
        """
        parent = self._cw.entity_from_eid(self.eidto)
        child = self._cw.entity_from_eid(self.eidfrom)
        group_name = parent.name
        if child.firstname is None or child.surname is None:
            user_name = child.login
        else:
            user_name = child.firstname + " " + child.surname
        if group_name in self._cw.vreg.config.get("restricted-groups", []):
            raise ConfigurationError(
                "You do not have sufficient permissions to administrate '%s' "
                "in the '%s' group." % (user_name, group_name))


class ExternalAuthSourceHook(hook.Hook):
    """ On startup ask for a login/password to contact the external destination
    authentification ldap based system. If not already specified create
    a 'SCHIIRDOR_SOURCE' and a 'SCHIIRDOR_DESTINATION' sources.

    This class raise a 'ConfigurationError' if a secret key with
    0 < len(key) <= 32 is not specified.
    """
    __regid__ = "external-auth-source-hook"
    src_name = "SCHIIRDOR_SOURCE"
    src_rql = ("Any X, T, U, C Where X is CWSource, X name 'SCHIIRDOR_SOURCE', "
               "X type T, X url U, X config C")
    events = ("server_startup", )

    def __call__(self):
        """ Important registery parameters are the 'dest_authlogin' and
        'dest_authpassword' used to contact the authentification ldap based
        system.
        """
        # Small hack copied from the trustedauth cube to make sure the secret
        # key file is loaded on both sides of cw (repo and web)
        secretfile = self.repo.vreg.config.get(KEYCONFENTRY) or ""
        secretfile = secretfile.strip()
        if not secretfile:
            raise ConfigurationError(
                "Configuration '%s' is missing or empty. "
                "Please check your configuration file!" % KEYCONFENTRY)
        set_secret(self.repo.vreg.config, secretfile)

        # Make sure a login and password is provided to contact the external
        # sources on both sides of cw (repo and web)
        cyphr = build_cypher(self.repo.vreg.config._secret)
        src_file = self.repo.vreg.config.get(KEYINPUTSRC) or ""
        src_file = src_file.strip()
        if not src_file:
            raise ConfigurationError(
                "Configuration '%s' is missing or empty. "
                "Please check your configuration file!" % KEYINPUTSRC)
        src_login, src_password, src_url, src_config = load_source_config(
            src_file)
        self.repo.vreg.src_authlogin = base64.encodestring(
            cyphr.encrypt("%128s" % src_login))
        self.repo.vreg.src_authpassword = base64.encodestring(
            cyphr.encrypt("%128s" % src_password))
        dest_file = self.repo.vreg.config.get(KEYOUTPUTSRC) or ""
        dest_file = dest_file.strip()
        if not dest_file:
            raise ConfigurationError(
                "Configuration '%s' is missing or empty. "
                "Please check your configuration file!" % KEYOUTPUTSRC)
        dest_login, dest_password, dest_url, dest_config = load_source_config(
            dest_file)
        self.repo.vreg.dest_authlogin = base64.encodestring(
            cyphr.encrypt("%128s" % dest_login))
        self.repo.vreg.dest_authpassword = base64.encodestring(
            cyphr.encrypt("%128s" % dest_password))

        # Create or update source
        with self.repo.internal_cnx() as cnx:
            _create_or_update_ldap_data_source(
                cnx, src_url, src_config, dest_url, dest_config, update=False)

        # Check if the source are active or not
        if self.repo.vreg.config.get(KEYDISABLEENTRY, False):
            LDAPFeedSource.disabled = True
        # Update repository cache for source synchronization
        else:
            raise NotImplementedError("The trick to deal with the cubicweb "
                                      "ldap sync is not implemented.")
            # with self.repo.internal_cnx() as cnx:
            #     rset = cnx.execute(self.src_rql)
            # if rset.rowcount != 1:
            #     raise Exception("No resource attached to this RQL: "
            #                     "{0}.".format(self.src_rql))
            # seid, stype, surl, sconfig = rset[0]
            # if stype != "ldapfeed":
            #     raise Exception("Source '{0}' must be of 'ldapfeed' "
            #                     "type.".format(self.src_name))
            # config = LDAPConnection.configure(
            #     seid, self.src_name, stype, surl, sconfig, login, password)
            # with self.repo.internal_cnx() as cnx:
            #     rset = cnx.execute("Any X WHERE X is CWGroup")
            #     for egroup in rset.entities():
            #         if egroup.name in ["guests", "managers", "users", "owners"]:
            #             continue
            #         self.repo._extid_cache["cn={0},{1}".format(
            #             egroup.name, config["group-base-dn"])] = egroup.eid


def load_source_config(sourcefile):
    """ Load a source defined in the instance configuration file.
    """
    with open(sourcefile, "rt") as open_file:
        config = json.load(open_file)
    if "login" not in config:
        login = raw_input("Enter the destination LDAP based system login: ")
    else:
        login = config.pop("login")
    if "password" not in config:
        password = getpass.getpass(
            "Enter the destination LDAP based system password: ")
    else:
        password = config.pop("password")
    url = config.get("url") or ""
    url = url.strip()
    if not url:
        raise Exception("Please specify the LDAP server URL as 'url' "
                        "parameter in LDAP configuration file.")
    return login, password, url, config


def set_secret(config, secretfile):
    """ Set a '_secret' config parameter with the 32 bytes key available in the
    'registration-cypher-seed' configuration file.
    """
    try:
        secret = open(secretfile).read().strip()
    except IOError:
        raise ConfigurationError(
            "Cannot open secret key file. Check your configuration file!")
        return
    if not secret or len(secret) > 32:
        raise ConfigurationError(
            "Secret key must me a string 0 < len(key) <= 32.")
    config._secret = secret.ljust(32, "#")

