import os
import yaml
import logging
import shutil
from pyroute2 import IPRoute
logger = logging.getLogger(__name__)

from .exceptions import *


class Interfaces(object):
    """This class implements Fluffy interfaces"""

    reserved_interfaces = {
        'any': None
    }
    """dict: Reserved interfaces"""

    def __init__(self, interfaces, db):
        """Initialize an instance of the Intefaces class

        Args:
            interfaces (dict): A dictionary describing the interfaces
            db (str): Location to the interfaces database

        """

        self._rule_deps = {}
        """dict: Describes rules dependencies to interfaces entries"""

        self._interfaces = {}
        """dict: The interfaces entries"""

        # add the reserved interfaces first
        for name, interface in self.reserved_interfaces.iteritems():
            self.add(name, interface)

        for name, interface in interfaces.iteritems():
            self.add(name, interface)

        self._db = db
        """str: The interfaces database location"""

    def __getitem__(self, key):
        """Retrieve an interface

        Args:
            key (str): The interface to lookup

        Returns:
            dict: The looked up interface

        """

        return self.lookup(key)

    def __iter__(self):
        """Retrieve all interfaces

        Returns:
            iterator: The interfaces

        """

        return self._interfaces.iteritems()

    def update_objref(self, obj):
        """Update the interfaces

        Args:
            obj (Interfaces): The updated object

        """

        self._interfaces = obj.interfaces()
        self._rule_deps = obj.rule_deps()

    def interfaces(self):
        """Retrieve the interfaces

        Returns:
            dict: The interfaces

        """

        return self._interfaces

    def rule_deps(self):
        """Retrieve the rules dependencies on the interfaces

        Returns:
            dict: A dictionary describing the rule dependencies

        """

        return self._rule_deps

    def save(self):
        """Persist the interfaces to disk"""

        try:
            logger.debug("Backing up interfaces")
            if os.path.exists(self._db):
                shutil.copyfile(self._db, "{}.bak".format(self._db))
        except Exception as e:
            logger.exception("Failed to backup interfaces")
            return

        try:
            logger.debug("Saving interfaces")
            with open(self._db, 'w') as f:
                f.write(yaml.safe_dump(dict(((k, v) for (k, v) in self._interfaces.iteritems(
                ) if k not in self.reserved_interfaces)), default_flow_style=False, explicit_start=True))
        except Exception as e:
            logger.exception("Failed to save interfaces")

    def validate(self, name, interface):
        if interface in self._interfaces.values():
            raise Exception("Network interface already in use".format(interface))

        if not self.is_reserved(name):
            if not isinstance(interface, basestring):
                raise Exception("Network interface must be type string")

            # check that the network interface actually exists on the system
            ip = IPRoute()
            if not ip.link_lookup(ifname=interface):
                raise Exception("Network interface not found on the system")
            ip.close()

    def add(self, name, interface):
        """Add a new interface

        Args:
            name (str): The interface name
            interface (str): Network interface

        Raises:
            InterfaceExists, InterfaceNotValid

        """

        if self.exists(name):
            raise InterfaceExists("Interface name already exists")

        try:
            self.validate(name, interface)
        except Exception as e:
            raise InterfaceNotValid(e.message)

        self._interfaces[name] = interface
        self._rule_deps[name] = []

    def update(self, name, interface):
        """Update an existing interface

        Args:
            name (str): The interface name
            interface (str): Network interface

        Raises:
            InterfaceNotFound, InterfaceNotValid, InterfaceNotUpdated

        """

        if not self.exists(name):
            raise InterfaceNotFound("Interface not found")

        if self.is_reserved(name):
            raise InterfaceNotValid(
                "Interface cannot be altered as it is reserved")

        try:
            self.validate(name, interface)
        except Exception as e:
            raise InterfaceNotValid(e.message)

        if self._interface[name] != interface:
            self._interfaces[name] = interface
        else:
            raise InterfaceNotUpdated("No changes detected")

    def delete(self, name):
        """Delete an interface

        Args:
            name (str): Then interface name

        Raises:
            InterfaceNotFound, InterfaceInUse, InterfaceNotValid

        """

        if not self.exists(name):
            raise InterfaceNotFound("Interface not found")

        if self.is_reserved(name):
            raise InterfaceNotValid(
                "Interface cannot be deleted as it is reserved")

        if len(self._rule_deps[name]) > 0:
            raise InterfaceInUse(
                "Interface cannot be deleted as some rules are currently using it", deps=self._rule_deps[name])

        del self._interfaces[name]
        del self._rule_deps[name]

    def lookup(self, name):
        """Look up an interface

        Args:
            name (str): The interface

        Returns:
            dict: The looked up interface entry

        Raises:
            InterfaceNotFound

        """

        try:
            data_lookup = self._interfaces[name]
        except KeyError:
            raise InterfaceNotFound("Interface not found")

        return data_lookup

    def exists(self, name):
        """Returns whether an interface exists or not

        Args:
            name (str): The interface

        Returns:
            bool: True if the interface exists, else False

        """

        try:
            self.lookup(name)
        except InterfaceNotFound:
            return False

        return True

    def add_dep(self, interface, rule):
        """Add a rule dependency to the given interface entry

        Args:
            service (str): The interface name
            rule (str): The rule name

        Raises:
            InterfaceNotFound

        """

        if not self.exists(interface):
            raise InterfaceNotFound("Interface has not been defined")

        if rule not in self._rule_deps[interface]:
            self._rule_deps[interface].append(rule)

    def delete_dep(self, interface, rule):
        """Delete a rule dependency for the given interface entry

        Args:
            service (str): The interface name
            rule (str): The rule name

        Raises:
            InterfaceNotFound

        """

        if not self.exists(interface):
            raise InterfaceNotFound("Interface has not been defined")

        if rule in self._rule_deps[interface]:
            self._rule_deps[interface].remove(rule)

    @classmethod
    def is_reserved(cls, name):
        """Returns whether an interface is reserved or not

        Args:
            name (str): The interface

        Returns:
            bool: True if the interface is reserved, else False

        """

        return True if name in cls.reserved_interfaces else False

    @classmethod
    def load_yaml(cls, db):
        """Load the interfaces from the database

        Args:
            db (str): The interfaces database

        Returns:
            Interfaces: An instance of the Interfaces class

        Raises:
            RuntimeError

        """

        interfaces = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    interfaces = yaml.load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load interfaces ({})".format(e.message))

        return cls(interfaces=interfaces, db=db)
