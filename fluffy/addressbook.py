import os
import yaml
import logging
import shutil
logger = logging.getLogger(__name__)

from .exceptions import *
from .utils import *


class AddressBook(object):
    """This class implements the Fluffy addressbook"""

    reserved_addresses = {
        'any': ['0.0.0.0/0'],
        'any_broadcast': ['255.255.255.255']
    }
    """dict: Reserved addresses"""

    def __init__(self, addressbook, db):
        """Initialize an instance of the AddressBook class

        Args:
            addressbook (dict): A dictionary describing the addressbook
            db (str): Location to the addressbook database

        """

        self._rule_deps = {}
        """dict: Describes rules dependencies to addressbook entries"""

        self._loaded_addressbook = addressbook
        """dict: A reference to the addressbook being loaded"""

        self._addressbook = {}
        """dict: The addressbook entries"""

        self._addressbook_deps = {}
        """dict: Describes addressbook dependencies between entries"""

        # add the reserved addresses first
        for name, address in self.reserved_addresses.iteritems():
            self.add(name, address)

        for name, address in addressbook.iteritems():
            self.add(name, address, init=True)

        self._db = db
        """str: The addressbook database location"""

    def __getitem__(self, key):
        """Retrieve an address

        Args:
            key (str): The address to lookup

        Returns:
            list: The looked up address

        """

        return self.lookup(key)

    def __iter__(self):
        """Retrieve the addressbook

        Returns:
            iterator: The addressbook

        """

        for name, address in self._addressbook.iteritems():
            yield name, self.lookup(address, recurse=True)

    def update_objref(self, obj):
        """Update the addressbook

        Args:
            obj (AddressBook): The updated object

        """

        self._addressbook = obj.addressbook()
        self._rule_deps = obj.rule_deps()

    def rule_deps(self):
        """Retrieve the rules dependencies on the addressbook

        Returns:
            dict: A dictionary describing the rule dependencies

        """

        return self._rule_deps

    def addressbook(self):
        """Retrieve the addressbook

        Returns:
            dict: The addressbook

        """

        return self._addressbook

    def get(self, recurse=True):
        """Retrieve the addressbook.

        Args:
            recurse (bool): Enable recusive look up in the addressbook

        Returns:
            iterator: The addressbook

        """

        for name, address in self._addressbook.iteritems():
            if recurse:
                yield name, self.lookup(address, recurse)
            else:
                yield name, address

    def save(self):
        """Persist the addressbook to disk"""

        try:
            logger.debug("Backing up addressbook")
            if os.path.exists(self._db):
                shutil.copyfile(self._db, "{}.bak".format(self._db))
        except Exception as e:
            logger.exception("Failed to backup addressbook")
            return

        try:
            logger.debug("Saving addressbook")
            with open(self._db, 'w') as f:
                f.write(yaml.safe_dump(dict(((k, v) for (k, v) in self._addressbook.iteritems(
                ) if k not in self.reserved_addresses)), default_flow_style=False, explicit_start=True))
        except Exception as e:
            logger.exception("Failed to save addressbook")

    def add(self, name, address, init=False):
        """Add a new address

        Args:
            name (str): The address name
            address (str): The address entry
            init (bool): If True, it disables any dependencies checks.

        Raises:
            AddressExists, AddressNotValid

        """

        if self.exists(name):
            raise AddressExists("Address name already exists")

        if isinstance(address, list):
            values = address
        else:
            values = [address]

        addressbook_deps = []
        for value in values:
            if is_valid_cidr(value) or is_valid_iprange(value):
                continue
            elif value in self._addressbook or (init == True and value in self._loaded_addressbook):
                addressbook_deps.append(value)
            else:
                raise AddressNotValid(
                    "Address '{}' must be a valid CIDR, an IP range or a reference to another address in the addressbook".format(value))

        self._addressbook[name] = values
        self._rule_deps[name] = []

        # manage dependencies
        if name not in self._addressbook_deps:
            self._addressbook_deps[name] = []

        for addr in addressbook_deps:
            if addr not in self._addressbook_deps:
                self._addressbook_deps[addr] = []

            self._addressbook_deps[addr].append(name)

    def update(self, name, address):
        """Update an existing address

        Args:
            name (str): The address name
            address (str): The updated address entry

        Raises:
            AddressNotFound, AddressNotValid, AddressNotUpdated

        """

        if not self.exists(name):
            raise AddressNotFound("Address not found")

        if self.is_reserved(name):
            raise AddressNotValid(
                "Address cannot be altered as it is reserved")

        if isinstance(address, list):
            values = address
        else:
            values = [address]

        addressbook_deps = []
        for value in values:
            if is_valid_cidr(value):
                continue
            elif is_valid_iprange(value):
                continue
            elif value in self._addressbook:
                addressbook_deps.append(value)
            else:
                raise AddressNotValid(
                    "Address '{}' must be a valid CIDR, an IP range or a reference to another address in the addressbook".format(value))

        if self._addressbook[name] == address:
            raise AddressNotUpdated("No changes detected")

        # update the dependencies
        for addr in list(set(self._addressbook[name]) - set(addressbook_deps)):
            if addr in self._addressbook_deps:
                self._addressbook_deps[addr].remove(name)

        for addr in list(set(addressbook_deps) - set(self._addressbook_deps[name])):
            if addr in self._addressbook_deps:
                self._addressbook_deps[addr].append(name)

        # update the address
        self._addressbook[name] = values

    def delete(self, name):
        """Delete an address

        Args:
            name (str): The address name

        Raises:
            AddressNotFound, AddressInUse, AddressNotValid

        """

        if not self.exists(name):
            raise AddressNotFound("Address not found")

        if self.is_reserved(name):
            raise AddressNotValid(
                "Address cannot be deleted as it is reserved")

        if len(self._rule_deps[name]) > 0:
            raise AddressInUse(
                "Address cannot be deleted as some rules are currently using it", deps=self._rule_deps[name])

        # FIXME: is the address currently in use by other addresses?
        if len(self._addressbook_deps[name]) > 0:
            raise AddressInUse(
                "Address cannot be deleted as some addressbook entries are currently using it", deps=self._addressbook_deps[name])

        del self._addressbook[name]
        del self._addressbook_deps[name]
        del self._rule_deps[name]

    def lookup(self, name, recurse=True):
        """Look up an address

        Args:
            name (str): The address
            recurse (bool): Enable recursive lookup

        Returns:
            list: The looked up address entry

        Raises:
            AddressNotFound

        """

        if is_valid_cidr(name):
            return name
        elif is_valid_iprange(name):
            return name
        elif isinstance(name, list):
            r = []
            for a in name:
                if recurse:
                    r.append(self.lookup(a, recurse))
                else:
                    r.append(a)

            return flatten(r)
        else:
            try:
                data_lookup = self._addressbook[name]
            except KeyError:
                raise AddressNotFound("Address not found")

            if recurse:
                return self.lookup(data_lookup)
            else:
                return data_lookup

    def exists(self, name):
        """Returns whether an address exists or not

        Args:
            name (str): The address

        Returns:
            bool: True if the address exists, else False

        """

        try:
            self._addressbook[name]
        except KeyError:
            return False

        return True

    def add_dep(self, address, rule):
        """Add a rule dependency to the given address entry

        Args:
            address (str): The address name
            rule (str): The rule name

        Raises:
            AddressNotFound

        """

        if not self.exists(address):
            raise AddressNotFound("Address has not been defined")

        if rule not in self._rule_deps[address]:
            self._rule_deps[address].append(rule)

    def delete_dep(self, address, rule):
        """Delete a rule dependency for the given address entry

        Args:
            address (str): The address name
            rule (str): The rule name

        Raises:
            AddressNotFound

        """

        if not self.exists(address):
            raise AddressNotFound("Address has not been defined")

        if rule in self._rule_deps[address]:
            self._rule_deps[address].remove(rule)

    @classmethod
    def is_reserved(cls, name):
        """Returns whether an address is reserved or not

        Args:
            name (str): The address

        Returns:
            bool: True if the address is reserved, else False

        """

        return True if name in cls.reserved_addresses else False

    @classmethod
    def load_yaml(cls, db):
        """Load the addressbook from the database

        Args:
            db (str): The addressbook database

        Returns:
            AddressBook: An instance of the AddressBook class

        Raises:
            RuntimeError

        """

        addressbook = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    addressbook = yaml.load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load addressbook ({})".format(e.message))

        return cls(addressbook=addressbook, db=db)
