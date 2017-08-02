import os
import yaml
import logging
import shutil
logger = logging.getLogger(__name__)

from .exceptions import *


class Interfaces(object):
    reserved_interfaces = {
        'any': None
    }

    def __init__(self, interfaces, db):
        self._rule_deps = {}
        self._interfaces = {}

        # add the reserved interfaces first
        for name, interface in self.reserved_interfaces.iteritems():
            self.add(name, interface)

        for name, interface in interfaces.iteritems():
            self.add(name, interface)

        self._db = db

    def __getitem__(self, key):
        return self.lookup(key)

    def __iter__(self):
        return self._interfaces.iteritems()

    def update_objref(self, obj):
        self._interfaces = obj.interfaces()
        self._rule_deps = obj.rule_deps()

    def interfaces(self):
        return self._interfaces

    def rule_deps(self):
        return self._rule_deps

    def all(self):
        for name, interface in self._interfaces.iteritems():
            yield name, interface

    @classmethod
    def is_reserved(cls, name):
        return True if name in cls.reserved_interfaces else False

    @classmethod
    def load_yaml(cls, db):
        interfaces = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    interfaces = yaml.load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load interfaces ({})".format(e.message))

        return cls(interfaces=interfaces, db=db)

    def save(self):
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

    def add(self, name, interface):
        if self.exists(name):
            raise InterfaceExists("Interface name already exists")

        self._interfaces[name] = interface
        self._rule_deps[name] = []

    def update(self, name, interface):
        if not self.exists(name):
            raise InterfaceNotFound("Interface not found")

        if self.is_reserved(name):
            raise InterfaceNotValid(
                "Interface cannot be altered as it is reserved")

        if self._interface[name] != interface:
            self._interfaces[name] = interface
        else:
            raise InterfaceNotUpdated("No changes detected")

    def delete(self, name):
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
        try:
            data_lookup = self._interfaces[name]
        except KeyError:
            raise InterfaceNotFound("Interface not found")

        return data_lookup

    def exists(self, name):
        try:
            self.lookup(name)
        except InterfaceNotFound:
            return False

        return True

    def add_dep(self, interface, rule):
        if not self.exists(interface):
            raise InterfaceNotFound("Interface has not been defined")

        if rule not in self._rule_deps[interface]:
            self._rule_deps[interface].append(rule)

    def delete_dep(self, interface, rule):
        if not self.exists(interface):
            raise InterfaceNotFound("Interface has not been defined")

        if rule in self._rule_deps[interface]:
            self._rule_deps[interface].remove(rule)
