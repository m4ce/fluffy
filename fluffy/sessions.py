import os
import sys
import copy
import tempfile
import subprocess32 as subprocess
import glob
import atexit
from jinja2 import Environment, FileSystemLoader
from threading import Timer, Thread, Lock
from multiprocessing import Process, Queue
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from unshare import unshare, CLONE_NEWNET

from datetime import datetime, timedelta

from .exceptions import *

import logging
logger = logging.getLogger(__name__)

global_commit_lock = Lock()
"""Lock: global lock for committing session configuration to active"""


class Sessions(object):
    """This class implements the Fluffy sessions"""

    def __init__(self, rules, data_dir, checks, max_sessions):
        """Initialize an instance of the Sessions class

        Args:
            rules (Rules): The active rules
            checks (Checks): The active checks
            max_sessions (int): The maximum number of sessions allowed

        """

        self._sessions = {}
        """dict: The current sessions"""

        self._active_rules = rules
        """dict: Reference to the active rules"""

        self._sessions_dir = os.path.join(data_dir, 'sessions')
        """dict: The sessions directory"""

        self._templates_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'iptables')
        """dict: The templates location"""

        self._active_checks = checks
        """dict: The active checks"""

        self._max_sessions = max_sessions
        """dict: The maximum number of sessions allowed"""

        # Thread pool
        self._executor = ThreadPoolExecutor(max_sessions)
        """dict: The ThreadPoolExecutor service"""

        # TTL timers
        self._expiration_timers = {}
        """dict: Timers for sessions expiration"""

        # synchronize delete operations
        self._delete_lock = Lock()
        """dict: A lock to synchronize sessions deletions"""

        # create sessions directory
        if not os.path.exists(self._sessions_dir):
            logger.info("Creating sessions directory ({})".format(
                self._sessions_dir))
            try:
                os.makedirs(self._sessions_dir)
            except Exception as e:
                logger.exception("Failed to create sessions directory")
                sys.exit(1)

        atexit.register(self._exit)

    def __getitem__(self, key):
        """Retrieve a session

        Args:
            key (str): The session to lookup

        Returns:
            dict: The looked up session

        """

        return self.lookup(key)

    def __iter__(self):
        """Retrieve all sessions

        Returns:
            iterator: The sessions

        """

        return self._sessions.iteritems()

    def add(self, name, ttl=3600, owner=None):
        """Add a new session

        Args:
            name (str): The session name
            ttl (int): The session TTL
            owner (Optional[str]): The session owner

        Raises:
            SessionExists, SessionNotValid, SessionError

        """

        if self.exists(name):
            raise SessionExists("Session already exists")

        if not isinstance(ttl, int) or not ttl > 0:
            raise SessionNotValid("Session TTL is required")

        if len(self._sessions) > self._max_sessions:
            raise SessionError("Maximum number of sessions reached")

        logger.info(
            'Created new session {} (owner: {}, ttl: {}s)'.format(name, owner, ttl))
        self._sessions[name] = Session(
            name=name,
            rules=self._active_rules,
            checks=self._active_checks,
            sessions_dir=self._sessions_dir,
            templates_dir=self._templates_dir,
            owner=owner,
            ttl=ttl,
            executor=self._executor
        )

        self._expiration_timers[name] = Timer(ttl, self._expire, args=[name])
        self._expiration_timers[name].daemon = True
        self._expiration_timers[name].start()

        return self._sessions[name]

    def _expire(self, name):
        """Expire a session

        Args:
            name (str): The session name

        """

        logger.warning(
            "Session {} TTL has expired, deleting session".format(name))
        try:
            self.delete(name)
        except SessionNotFound:
            pass

    def delete(self, name):
        """Delete a session

        Args:
            name (str): The session name

        Raises:
            SessionNotFound

        """

        with self._delete_lock:
            if not self.exists(name):
                raise SessionNotFound("Session not found")

            self._sessions[name].close()
            del self._sessions[name]
            logger.info('Deleted session {}'.format(name))

            # Remove any active expiration timer for the session
            if self._expiration_timers[name]:
                self._expiration_timers[name].cancel()
                del self._expiration_timers[name]

    def exists(self, name):
        """Returns whether a session exists or not

        Args:
            name (str): The rule

        Returns:
            bool: True if the session exists, else False

        """

        try:
            self.lookup(name)
        except SessionNotFound:
            return False

        return True

    def lookup(self, name):
        """Look up a session

        Args:
            name (str): The session

        Returns:
            dict: The looked up session entry

        Raises:
            SessionNotFound

        """

        try:
            return self._sessions[name]
        except KeyError:
            raise SessionNotFound("Session not found")

    def _exit(self):
        """Function invoked on exit"""

        for name in self._sessions.keys():
            self.delete(name)

        self._executor.shutdown(wait=True)


class Session(object):
    def __init__(self, name, rules, checks, sessions_dir, templates_dir, owner, ttl, executor):
        self._name = name
        """str: The session name"""

        self._active_rules = rules
        """Rules: Reference to the active rules"""

        self._active_chains = rules.chains
        """Chains: Reference to the active chains"""

        self._active_addressbook = rules.addressbook
        """AddressBook: Reference to the active addressbook"""

        self._active_interfaces = rules.interfaces
        """Interfaces: Reference to the active interfaces"""

        self._active_services = rules.services
        """Services: Reference to the active services"""

        self._active_checks = checks
        """Checks: Reference to the active checks"""

        self._sessions_dir = sessions_dir
        """str: The sessions directory"""

        self._templates_dir = templates_dir
        """str: The templates directory"""

        self._current = copy.deepcopy(rules)
        """Rules: Copy of the active rules at the start of the session"""

        self._current_rules = self._current
        """Rules: Reference to the active rules at the start of the session"""

        self._current_chains = self._current.chains
        """Chains: Reference to the active chains at the start of the session"""

        self._current_addressbook = self._current.addressbook
        """AddressBook: Reference to the active addresbook at the start of the session"""

        self._current_interfaces = self._current.interfaces
        """Interfaces: Reference to the active interfaces at the start of the session"""

        self._current_services = self._current.services
        """Services: Reference to the active services at the start of the session"""

        self._current_checks = copy.deepcopy(checks)
        """Checks: Reference to the active checks at the start of the session"""

        # this will be the session configuration
        self.rules = copy.deepcopy(self._current)
        """Rules: The session rules"""

        self.addressbook = self.rules.addressbook
        """AddressBook: The session addressbook"""

        self.chains = self.rules.chains
        """Chains: The session chains"""

        self.interfaces = self.rules.interfaces
        """Interfaces: The session interfaces"""

        self.services = self.rules.services
        """Services: The session services"""

        self.checks = copy.deepcopy(self._current_checks)
        """Checks: The session checks"""

        self._status = None
        self._commit_job = None

        self._committed = False
        """bool: Whether the session configuration has been committed or not"""

        self._confirmed = False
        """bool: Whether the session configuration has been confirmed or not"""

        self._rollback_timer = None
        """Timer: The rollback timer"""

        self._rollback_timer_start = None
        """datetime: The rollback timer start time"""

        self._owner = owner
        """str: The session owner"""

        self._ttl = ttl
        """int: The session TTL"""

        self._executor = executor
        """ThreadPoolExecutor: The executor service"""

        self._rollback_cancel_lock = Lock()
        """Lock: The session rollback cancel timer lock"""

        self._confirm_lock = Lock()
        """Lock: The session confirm lock"""

        atexit.register(self.close)

    def name(self):
        """Returns the session's name

        Returns:
            str: The session's name

        """

        return self._name

    def owner(self):
        """Returns the session's owner

        Returns:
            str: The session's owner

        """

        return self._owner

    def ttl(self):
        """Returns the session's TTL

        Returns:
            int: The session's TTL

        """

        return self._ttl

    def committed(self):
        """Returns whether the session's configuration has been committed or not

        Returns:
            bool: True if the session's configuration has been committed, else False

        """

        return self._committed

    def confirmed(self):
        """Returns whether the session's configuration has been confirmed or not

        Returns:
            bool: True if the session's configuration has been confirmed, else False

        """

        return self._confirmed

    def _commit_in_progress(self):
        if self._commit_job:
            return self._commit_job.running()
            # return self._commit_thr.isAlive()

        return False

    def _rollback_in_progress(self):
        return True if self._rollback_timer else False

    def _rollback_seconds_left(self):
        if self._rollback_timer_start:
            return (self._rollback_timer_start - datetime.now()).seconds

        return None

    def build(self, chains, interfaces, addressbook, rules, services):
        """Build IPTables rules from the session's configuration

        Args:
            chains (Chains): The chains
            interfaces (Interfaces): The interfaces
            addressbook (AddressBook): The interfaces
            rules (Rules): The rules
            services (Services): The services

        Returns:
            list: IPTables firewall rules

        """

        ret = []

        j2env = Environment(loader=FileSystemLoader(
            self._templates_dir), trim_blocks=True)
        ret.append(j2env.get_template(
            'header.jinja').render({'name': self.name()}))

        # flush tables first
        for table in ['filter', 'nat', 'mangle', 'raw', 'security']:
            ret.append(j2env.get_template(
                'flush.jinja').render({'table': table}))

        builtin_chains = []
        userdef_chains = []
        for table_name, table_chains in chains:
            for chain_name, chain in table_chains.iteritems():
                builtin = chains.is_builtin(name=chain_name, table=table_name)
                tmpl = j2env.get_template('chain.jinja').render(
                    {'name': chain_name, 'table': table_name, 'chain': chain, 'builtin': builtin})
                # check if chain is a default one
                if builtin:
                    builtin_chains.append(tmpl)
                else:
                    ret.append(tmpl)
                    userdef_chains.append(j2env.get_template('rule.jinja').render({'rule': {
                                          'chain': chain_name, 'table': table_name, 'action': chain['policy'], 'comment': 'default_chain_policy'}}))

        # compute interfaces
        i_rules = OrderedDict()
        for name, rule in rules:
            # both input and output interfaces
            if rule['in_interface'] and rule['out_interface']:
                for in_interface in rule['in_interface']:
                    for out_interface in rule['out_interface']:
                        r = rule.copy()
                        r['in_interface'] = self.interfaces[in_interface]
                        r['out_interface'] = self.interfaces[out_interface]
                        i_rules[name] = r
            # only input interfaces
            elif rule['in_interface']:
                for in_interface in rule['in_interface']:
                    r = rule.copy()
                    r['in_interface'] = self.interfaces[in_interface]
                    i_rules[name] = r
            # only output interfaces
            elif rule['out_interface']:
                for out_interface in rule['out_interface']:
                    r = rule.copy()
                    r['out_interface'] = self.interfaces[out_interface]
                    i_rules[name] = r
            # no interfaces
            else:
                i_rules[name] = rule

        p_rules = OrderedDict()
        for name, rule in i_rules.iteritems():
            if rule['protocol']:
                # compute protocol combinations
                for protocol in rule['protocol']:
                    r = rule.copy()
                    r['protocol'] = protocol if protocol != 'any' else 'all'
                    p_rules[name] = r
            else:
                # handle services
                r = rule.copy()
                for attr_key in [('src_service', 'src_port'), ('dst_service', 'dst_port')]:
                    if rule[attr_key[0]]:
                        r[attr_key[0]] = []
                        for value in rule[attr_key[0]]:
                            data_lookup = self.services[value]
                            r[attr_key[0]] += data_lookup[attr_key[1]]

                            if not r['protocol']:
                                r['protocol'] = data_lookup['protocol'] if data_lookup['protocol'] != 'any' else 'all'

                p_rules[name] = r

        # compute everything else
        for name, rule in p_rules.iteritems():
            r = rule.copy()
            for attr_key in ['src_address_range', 'dst_address_range', 'src_address', 'dst_address']:
                if rule[attr_key]:
                    r[attr_key] = []
                    for value in rule[attr_key]:
                        data_lookup = self.addressbook[value]
                        if isinstance(data_lookup, list):
                            r[attr_key] += data_lookup
                        else:
                            r[attr_key].append(data_lookup)

            r['comment'] = name
            if rule['comment']:
                r['comment'] = "{}: {}".format(name, rule['comment'])
            else:
                r['comment'] = name

            ret.append(j2env.get_template('rule.jinja').render(
                {'name': name, 'rule': r}))

        ret += userdef_chains
        ret += builtin_chains
        return ret

    def test(self):
        """Test IPTables firewall rules

        Returns:
            (bool, Optional[str]): A tuple with the first object being True if the test succeeded, else False. The second object is a string storing an optional error message.

        """

        rules = self.build(chains=self.chains, interfaces=self.interfaces,
                           addressbook=self.addressbook, rules=self.rules, services=self.services)
        tmpfile = tempfile.NamedTemporaryFile(
            dir=self._sessions_dir, prefix='test_', delete=False)
        tmpfile.write("\n".join(rules))
        tmpfile.close()
        os.chmod(tmpfile.name, 0755)

        q = Queue()
        p = Process(target=self._test, args=(tmpfile.name, q))
        p.start()
        p.join()

        os.remove(tmpfile.name)

        return q.get()

    def _test(self, rules_file, queue):
        # Import the firewall rules in a detached network namespace
        unshare(CLONE_NEWNET)
        proc = subprocess.Popen(rules_file,
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

        if proc.returncode:
            queue.put((False, err.strip()))
        else:
            queue.put((True, None))

    def _cancel_rollback(self):
        with self._rollback_cancel_lock:
            logger.info(
                "Canceling rollback timer in session {}".format(self.name()))
            if self._rollback_timer:
                self._rollback_timer.cancel()
            self._rollback_timer = None
            self._rollback_timer_start = None

    def rollback(self):
        """Rollback configuration"""

        with self._confirm_lock:
            if self.confirmed():
                raise SessionError(
                    "Will not rollback as configuration has already been confirmed")

            logger.warning(
                "Rolling back configuration in session {}".format(self.name()))
            rules = self.build(chains=self._active_chains, interfaces=self._active_interfaces,
                               addressbook=self._active_addressbook, rules=self._active_rules, services=self._active_services)
            self._load(rules)
            self._committed = False
            self._status = "Configuration not confirmed - rolled back"

        # cancel the rollback timer - just in case
        if self._rollback_in_progress():
            self._cancel_rollback()

    def _load(self, rules):
        """Load IPTables rules

        Args:
            list: IPTables rules

        Returns:
            (int, Optional[str]): A tuple where the first object is the return code and the second is an optional error string associated to the return code.

        """

        tmpfile = tempfile.NamedTemporaryFile(
            dir=self._sessions_dir, delete=False)
        tmpfile.write("\n".join(rules))
        tmpfile.close()
        os.chmod(tmpfile.name, 0755)
        proc = subprocess.Popen(tmpfile.name, shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        os.remove(tmpfile.name)

        return proc.returncode, err

    def _has_active_configuration_changed(self):
        return (dict(self._current_addressbook) != dict(self._active_addressbook) or dict(self._current_interfaces) != dict(self._active_interfaces) or dict(self._current_chains) != dict(self._active_chains) or dict(self._current_services) != dict(self._active_services) or OrderedDict(self._current_rules) != OrderedDict(self._active_rules))

    def _commit(self, rules, force, rollback, rollback_interval):
        if not force:
            ok, err = self.test()
            if ok:
                logger.info(
                    "Configuration tested successfully in session {}".format(self.name()))
            else:
                raise SessionCommitError(
                    "Configuration test failure (Error: {})".format(err))

        # global lock
        logger.debug(
            "Waiting to acquire global commit lock in session {}".format(self.name()))
        self._status = 'Waiting to acquire global commit lock ..'
        with global_commit_lock:
            logger.debug(
                "Global commit lock acquired in session {}".format(self.name()))
            self._status = 'Configuration commit in progress (lock acquired)'

            # has the initial session configuration shifted from the active?
            if self._has_active_configuration_changed():
                raise SessionCommitError(
                    "The active configuration appears to have changed since the start of the session. Commit aborted.")

            exitcode, err = self._load(rules)
            if exitcode:
                if rollback:
                    self.rollback()
                    raise SessionCommitError(
                        "Configuration rolled back due to an error during the import process (Error: {})".format(err.strip()))
                else:
                    raise SessionCommitError(
                        "Configuration error during the import process (Error: {})".format(err.strip()))

            self._committed = True
            logger.info(
                "Configuration committed in session {}".format(self.name()))
            self._status = 'Configuration commited'

            if rollback:
                logger.info(
                    "Running rollback checks in session {}".format(self.name()))
                for check_name, check in self.checks:
                    logger.info("Running check '{}'".format(check_name))
                    try:
                        self.checks.run(check_name)
                    except CheckError as e:
                        self.rollback()
                        raise SessionCommitError(
                            "Check '{}' failed ({})".format(check_name, e.message))

                if rollback_interval and rollback_interval > 0:
                    logger.info("Set up rollback timer in session {} with a timeout of {}s".format(
                        self.name(), rollback_interval))
                    self._rollback_timer = Timer(
                        rollback_interval, self.rollback)
                    self._rollback_timer.daemon = True
                    self._rollback_timer.start()
                    self._rollback_timer_start = datetime.now() + timedelta(seconds=rollback_interval)
                    self._rollback_timer.join()
                else:
                    self.confirm()
            else:
                self.confirm()
        logger.debug(
            "Global commit lock released in session {}".format(self.name()))

    def confirm(self):
        """Confirm configuration"""

        if self.confirmed():
            raise SessionError("Configuration already confirmed")

        with self._confirm_lock:
            if self.committed():
                # update the active rules
                self._active_rules.update_objref(self.rules)

                # update the active addressbook
                self._active_addressbook.update_objref(self.addressbook)

                # update the active interfaces
                self._active_interfaces.update_objref(self.interfaces)

                # update the active chains
                self._active_chains.update_objref(self.chains)

                # update the active services
                self._active_services.update_objref(self.services)

                # update the active rollback checks
                self._active_checks.update_objref(self.checks)

                # confirm the commit
                self._confirmed = True

                logger.info(
                    "Configuration confirmed in session {}".format(self.name()))

                # cancel rollback timer if active
                if self._rollback_in_progress():
                    self._cancel_rollback()

                # set status
                self._status = 'Configuration has been committed and confirmed'
            else:
                raise SessionError("No outstanding commit to confirm")

    def _async_commit(self, rules, force, rollback, rollback_interval):
        try:
            self._commit(rules=rules, force=force, rollback=rollback,
                         rollback_interval=rollback_interval)
        except SessionCommitError as e:
            self._status = e.message
            logger.error(
                "Failed to commit configuration in session {} - {}".format(self.name(), e.message))

    def commit(self, force=False, async=False, rollback=True, rollback_interval=60):
        """Commit configuration

        Args:
            force (bool): Force commit even though no changes have been made
            async (bool): Perform commit asynchronously
            rollback (bool): Enable rollback in case of errors
            rollback_interval (int): Rollback configuration after the given internal unless confirmed

        """

        if self.confirmed():
            raise SessionError("Configuration already committed and confirmed")

        if self.committed():
            raise SessionError("Configuration already committed")

        if self._commit_in_progress():
            raise SessionError("Configuration commit already in progress")

        if not force:
            if dict(self._current_addressbook) == dict(self.addressbook) and dict(self._current_interfaces) == dict(self.interfaces) and dict(self._current_chains) == dict(self.chains) and dict(self._current_services) == dict(self.services) and OrderedDict(self._current_rules) == OrderedDict(self.rules):
                raise SessionError("No configuration changes detected")

        rules = self.build(chains=self.chains, interfaces=self.interfaces,
                           addressbook=self.addressbook, rules=self.rules, services=self.services)
        if async:
            self.__commit_job = self._executor.submit(
                self._async_commit, **{'rules': rules, 'force': force, 'rollback': rollback, 'rollback_interval': rollback_interval})
        else:
            self._commit(rules=rules, force=force, rollback=rollback,
                         rollback_interval=rollback_interval)

    def status(self):
        """Provide information about the active session

        Returns:
            info (dict): Information about the running session

        """

        info = {}
        info['owner'] = self.owner()
        info['ttl'] = self.ttl()
        info['committed'] = self.committed()
        info['confirmed'] = self.confirmed()

        if self._rollback_in_progress():
            info['status'] = "Configuration committed - rollback will take place in {}s unless configuration is confirmed".format(
                self._rollback_seconds_left())
        else:
            info['status'] = self._status

        return info

    def close(self):
        """Close session"""

        # cancel any outstanding rollback timer
        if self._rollback_in_progress():
            self._cancel_rollback()

        if self._commit_in_progress():
            logger.info(
                "Waiting for commit process to finish in session {}".format(self.name()))
            # self._commit_thr.join()
            self.__commit_job.result()

        if self.committed() and self.confirmed() == False:
            logger.warning(
                "Session {} is terminating - configuration has not been confirmed, forcing rollback".format(self.name()))
            self.rollback()
