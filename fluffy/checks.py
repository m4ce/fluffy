import os
import sys
import yaml
import logging
import shutil
import socket
if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
else:
    import subprocess
logger = logging.getLogger(__name__)

from .exceptions import *
from .utils import is_valid_port


class Checks(object):
    """This class implements the Fluffy checks"""

    defaults = {
        'type': None,
        'host': None,
        'port': None,
        'command': None,
        'timeout': 5
    }

    def __init__(self, checks, db):
        """Initialize an instance of the Checks class

        Args:
            checks (dict): A dictionary describing the checks
            db (str): Location to the checks database

        """

        self._checks = {}
        """dict: The checks entries"""

        for name, check in checks.iteritems():
            self.add(name,  **check)

        self._db = db
        """str: The checks database location"""

    def __getitem__(self, key):
        """Retrieve a check

        Args:
            key (str): The check name

        """

        return self.lookup(key)

    def __iter__(self):
        """Retrieve the checks

        Returns:
            iterator: The checks

        """

        return self._checks.iteritems()

    def update_objref(self, obj):
        """Update the checks

        Args:
            obj (Checks): The updated object

        """

        self._checks = obj.checks()

    def checks(self):
        """Retrieve the checks

        Returns:
            dict: The checks

        """

        return self._checks

    def all(self):
        """Retrieve the checks

        Returns:
            iterator: The checks

        """

        for name, check in self._checks.iteritems():
            yield name, check

    def save(self):
        """Persist the checks to disk"""

        try:
            logger.debug("Backing up checks")
            if os.path.exists(self._db):
                shutil.copyfile(self._db, "{}.bak".format(self._db))
        except Exception as e:
            logger.exception("Failed to backup checks")
            return

        try:
            logger.debug("Saving checks")
            with open(self._db, 'w') as f:
                f.write(yaml.safe_dump(self._checks,
                                       default_flow_style=False, explicit_start=True))
        except:
            logger.exception("Failed to save checks")

    def add(self, name, **kwargs):
        """Add a new check

        Args:
            name (str): The check name
            **kwargs: Arbitrary keywords arguments

        Raises:
            CheckExists, CheckNotValid

        """

        if self.exists(name):
            raise CheckExists("Check already exists")

        for k in kwargs.keys():
            if k not in self.defaults.keys():
                raise CheckNotValid(
                    "Invalid check parameter '{}'".format(k))

        check = self.defaults.copy()
        check.update(kwargs)

        # validate check
        try:
            self.validate(check)
        except Exception as e:
            raise CheckNotValid(e.message)

        # add check
        self._checks[name] = check

    def update(self, name, **kwargs):
        """Update a check

        Args:
            name (str): The check name
            **kwargs: Arbitrary keywords arguments

        """

        allowed_keys = self.defaults.keys()
        for k in kwargs.keys():
            if k not in allowed_keys:
                raise CheckNotValid(
                    "Invalid check parameter '{}'".format(k))

        check = self._checks[name].copy()
        check.update(kwargs)

        # validate check
        try:
            self.validate(check)
        except Exception as e:
            raise CheckNotValid(e.message)

        # update check
        self._checks[name].update(check)

    def delete(self, name):
        """Delete a check

        Args:
            name (str): The check name

        Raises:
            CheckNotFound

        """

        if not self.exists(name):
            raise CheckNotFound("Check not found")

        del self._checks[name]

    def lookup(self, name):
        """Look up a check

        Args:
            name (str): The check name

        Returns:
            dict: The looked up check entry

        Raises:
            CheckNotFound

        """

        try:
            return self._checks[name]
        except KeyError:
            raise CheckNotFound("Check not found")

    def exists(self, name):
        """Returns whether a check exists or not

        Args:
            name (str): The check name

        Returns:
            bool: True if the check exists, else False

        Raises:
            CheckNotFound

        """

        try:
            self.lookup(name)
        except CheckNotFound:
            return False

        return True

    def run(self, name):
        """Run a check

        Raises:
            CheckError

        """

        if not self.exists(name):
            raise CheckNotFound("Check not found")

        if self._checks[name]['type'] == 'exec':
            proc = subprocess.Popen(
                self._checks[name]['command'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                out, err = proc.communicate(timeout=self._checks[name]['timeout'])
            except subprocess.TimeoutExpired as e:
                raise CheckError("Timed out")
            except Exception as e:
                raise CheckError(e.message)

            if proc.returncode:
                raise CheckError("Command failed with exitstatus {} [{}]".format(
                    proc.returncode, err.strip()))
        elif self._checks[name]['type'] == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._checks[name]['timeout'])
            try:
                result = sock.connect_ex(
                    (self._checks[name]['host'], self._checks[name]['port']))
                sock.close()
                if result != 0:
                    raise Exception("Connection failed (Errno: {})".format(result))
            except socket.timeout as e:
                raise CheckError("Timed out")
            except Exception as e:
                raise CheckError(e.message)
            finally:
                sock.close()

    @classmethod
    def load_yaml(cls, db):
        """Load the checks from the database

        Args:
            db (str): The checks database

        Returns:
            Checks: An instance of the Checks class

        Raises:
            RuntimeError

        """

        checks = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    checks = yaml.load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load checks ({})".format(e.message))

        return cls(checks=checks, db=db)

    @classmethod
    def validate(cls, check):
        """Validate check

        Args:
            check (dict): A dictionary describing the check

        """

        if check['type'] not in ['tcp', 'exec']:
            raise Exception("Invalid check type")

        if check['type'] == 'tcp':
            if check['host'] is None:
                raise Exception("Host is required for TCP based checks")

            if check['port'] is None:
                raise Exception("Port is required for TCP based checks")

            if not is_valid_port(check['port']):
                raise Exception("Invalid TCP port")
        elif check['type'] == 'exec':
            if check['command'] is None:
                raise Exception("Command is required for exec based checks")

        if not isinstance(check['timeout'], int) or not check['timeout'] > 0:
            raise Exception("Timeout must be an Integer and greater than zero")
