import os
import yaml
import logging
import shutil
logger = logging.getLogger(__name__)

from .exceptions import *


class Chains(object):
    """This class implements the Fluffy chains"""

    builtin_chains = {
        'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
        'nat': ['INPUT', 'OUTPUT', 'PREROUTING', 'POSTROUTING'],
        'mangle': ['INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING'],
        'raw': ['PREROUTING', 'OUTPUT'],
        'security': ['INPUT', 'FORWARD', 'OUTPUT']
    }
    """dict: Built-in chains"""

    def __init__(self, tables, db):
        """Initialize an instance of the Chains class

        Args:
            tables (dict): A dictionary describing the chains indexed by packet routing tables
            db (str): Location to the chains database

        """

        self._rule_deps = {}
        """dict: Describes rules dependencies to chain entries"""

        self._tables = {}
        """dict: The chains entries indexed by packet routing tables"""

        for table, chains in tables.iteritems():
            for name, chain in chains.iteritems():
                self.add(name, table, **chain)

        # Add missing built-in chains
        for table, chains in self.builtin_chains.iteritems():
            for name in chains:
                if not self.exists(name, table):
                    self.add(name, table)

        self._db = db
        """str: The chains database location"""

    def __iter__(self):
        """Retrieve the chains

        Returns:
            iterator: The chains

        """

        return self._tables.iteritems()

    def update_objref(self, obj):
        """Update the chains

        Args:
            obj (Chains): The updated object

        """

        self._tables = obj.tables()
        self._rule_deps = obj.rule_deps()

    def tables(self):
        """Retrieve the chains indexed by packet routing tables

        Returns:
            dict: The chains indexed by packet rotuing tables

        """

        return self._tables

    def rule_deps(self):
        """Retrieve the rules dependencies on the chains

        Returns:
            dict: A dictionary describing the rule dependencies

        """

        return self._rule_deps

    def save(self):
        """Persist the chains to disk"""

        try:
            logger.debug("Backing up chains")
            if os.path.exists(self._db):
                shutil.copyfile(self._db, "{}.bak".format(self._db))
        except Exception as e:
            logger.exception("Failed to backup chains")
            return

        try:
            logger.debug("Saving chains")
            with open(self._db, 'w') as f:
                f.write(yaml.safe_dump(self._tables,
                                       default_flow_style=False, explicit_start=True))
        except:
            logger.exception("Failed to save chains")

    def add(self, name, table, **kwargs):
        """Add a new chain

        Args:
            name (str): The chain name
            table (str): The table name
            **kwargs: Arbitrary keywords arguments

        Raises:
            ChainExists, ChainNotValid

        """

        # make sure chain name is uppercase and packet matching table
        # lowercase.
        name = name.upper()
        table = table.lower()

        if self.exists(name, table):
            raise ChainExists("Chain already exists")

        # check if it is a valid table
        if table not in ['filter', 'nat', 'mangle', 'raw', 'security']:
            raise ChainNotValid("Invalid packet matching table")

        defaults = {}
        if self.is_builtin(name, table):
            defaults['policy'] = 'ACCEPT'
        else:
            defaults['policy'] = 'RETURN'

        for k in kwargs.keys():
            if k not in defaults.keys():
                raise ChainNotValid("Invalid chain parameter '{}'".format(k))

        chain = defaults.copy()
        chain.update(kwargs)

        # validate chain
        try:
            self.validate(name, table, chain)
        except Exception as e:
            raise ChainNotValid(e.message)

        # define table if absent
        if table not in self._tables:
            self._tables[table] = {}
            self._rule_deps[table] = {}

        self._tables[table][name] = chain
        self._rule_deps[table][name] = []

    def update(self, name, table, **kwargs):
        """Update a chain

        Args:
            name (str): The chain name
            table (str): The table name
            **kwargs: Arbitrary keywords arguments

        Raises:
            ChainNotFound, ChainNotValid, ChainNotUpdated

        """

        # make sure chain name is uppercase and packet matching table
        # lowercase.
        name = name.upper()
        table = table.lower()

        if not self.exists(name, table):
            raise ChainNotFound("Chain not found")

        allowed_keys = ['policy']
        for k in kwargs.keys():
            if k not in allowed_keys:
                raise ChainNotValid("Invalid chain parameter '{}'".format(k))

        chain = self._tables[table][name].copy()
        chain.update(kwargs)

        # validate chain
        try:
            self.validate(name, table, chain)
        except Exception as e:
            raise ChainNotValid(e.message)

        # update the chain
        if self._tables[table][name] == chain:
            raise ChainNotUpdated("No changes detected")

        self._tables[table][name].update(chain)

    def delete(self, name, table):
        """Delete a chain

        Args:
            name (str): The chain name
            table (str): The table name

        Raises:
            ChainNotFound, ChainNotValid, ChainInUse

        """

        if not self.exists(name, table):
            raise ChainNotFound("Chain not found")

        if self.is_builtin(name, table):
            raise ChainNotValid("Built-in chains cannot be deleted")

        if len(self._rule_deps[table][name]) > 0:
            raise ChainInUse(
                "Chain cannot be deleted as some rules are currently using it", deps=self._rule_deps[table][name])

        del self._tables[table][name]
        del self._rule_deps[table][name]

    def lookup(self, name, table):
        """Look up a chain

        Args:
            name (str): The chain name
            table (str): The table name

        Returns:
            dict: The looked up chain entry

        Raises:
            ChainNotFound

        """

        try:
            return self._tables[table][name]
        except KeyError:
            raise ChainNotFound("Chain not found")

    def exists(self, name, table):
        """Returns whether a chain exists or not

        Args:
            name (str): The chain name
            table (str): The table name

        Returns:
            bool: True if the chain exists, else False

        Raises:
            ChainNotFound

        """

        try:
            self.lookup(name, table)
        except ChainNotFound:
            return False

        return True

    def add_dep(self, table, chain, rule):
        """Add a rule dependency to the given chain entry

        Args:
            chain (str): The chain name
            table (str): The table name
            rule (str): The rule name

        Raises:
            ChainNotFound

        """

        if not self.exists(chain, table):
            raise ChainNotFound("Chain not found")

        if rule not in self._rule_deps[table][chain]:
            self._rule_deps[table][chain].append(rule)

    def delete_dep(self, table, chain, rule):
        """Delete a rule dependency for the given chain entry

        Args:
            chain (str): The chain name
            table (str): The table name
            rule (str): The rule name

        Raises:
            ChainNotFound

        """

        if not self.exists(chain, table):
            raise ChainNotFound("Chain not found")

        if rule in self._rule_deps[table][chain]:
            self._rule_deps[table][chain].remove(rule)

    @classmethod
    def is_builtin(cls, name, table):
        """Returns whether a chain is built-in or not

        Args:
            name (str): The name of the chain
            table (str): The name of the routing table

        Returns:
            bool: True if the chain is built-in, else False

        """

        return True if name in cls.builtin_chains[table] else False

    @classmethod
    def load_yaml(cls, db):
        """Load the chains from the database

        Args:
            db (str): The chains database

        Returns:
            Chains: An instance of the Chains class

        Raises:
            RuntimeError

        """

        tables = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    tables = yaml.load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load tables ({})".format(e.message))

        return cls(tables=tables, db=db)

    @classmethod
    def validate(cls, name, table, chain):
        """Validate a chain's configuration

        Args:
            name (str): The chain name
            table (str) The table name
            chain (dict): The chain settings

        """

        chain['policy'] = chain['policy'].upper()

        if cls.is_builtin(name, table):
            if chain['policy'] not in ['ACCEPT', 'DROP']:
                raise Exception("Invalid policy for built-in chain")
        else:
            if chain['policy'] not in ['ACCEPT', 'DROP', 'RETURN']:
                raise Exception("Invalid policy for user-defined chain")
