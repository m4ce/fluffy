import os
import yaml
import logging
import shutil
logger = logging.getLogger(__name__)

from .exceptions import *
from .utils import *


class Services(object):
    defaults = {
        'protocol': None,
        'src_port': [],
        'dst_port': []
    }

    reserved_services = {
        'any': {
            'protocol': 'all',
            'src_port': '1:65535',
            'dst_port': '1:65535'
        }
    }

    def __init__(self, services, db):
        self._rule_deps = {}
        self._loaded_services = services
        self._services = {}

        # add the reserved servicees first
        for name, service in self.reserved_services.iteritems():
            self.add(name, **service)

        for name, service in services.iteritems():
            self.add(name, **service)

        self._db = db

    def __getitem__(self, key):
        return self.lookup(key)

    def __iter__(self):
        return self._services.iteritems()

    def update_objref(self, obj):
        self._services = obj.services()
        self._rule_deps = obj.rule_deps()

    def services(self):
        return self._services

    def rule_deps(self):
        return self._rule_deps

    @classmethod
    def is_reserved(cls, name):
        return True if name in cls.reserved_services else False

    @classmethod
    def load_yaml(cls, db):
        services = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    services = yaml.load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load services ({})".format(e.message))

        return cls(services=services, db=db)

    def save(self):
        try:
            logger.debug("Backing up services")
            if os.path.exists(self._db):
                shutil.copyfile(self._db, "{}.bak".format(self._db))
        except Exception as e:
            logger.exception("Failed to backup services")
            return

        try:
            logger.debug("Saving services")
            with open(self._db, 'w') as f:
                f.write(yaml.safe_dump(dict(((k, v) for (k, v) in self._services.iteritems(
                ) if k not in self.reserved_services)), default_flow_style=False, explicit_start=True))
        except Exception as e:
            logger.exception("Failed to save services")

    @classmethod
    def validate(cls, service):
        # Protoool
        if service['protocol'] not in ['ip', 'tcp', 'udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'vrrp', 'igmp', 'ipencap', 'ipv4', 'ipv6', 'ospf', 'gre', 'cbt', 'sctp', 'pim', 'all']:
            raise Exception("Invalid service protocol")

        # Convert to lists and unique elements
        for attr_key in ['src_port', 'dst_port']:
            if service[attr_key]:
                if isinstance(service[attr_key], list):
                    service[attr_key] = list(set(service[attr_key]))
                else:
                    service[attr_key] = list(set([service[attr_key]]))

        # Ports
        if service['dst_port'] is None and service['src_port'] is None:
            raise Exception("Either src_port or dst_port are required")

        # Check if we have valid ports
        for attr_key in ['dst_port', 'src_port']:
            if service[attr_key]:
                for port in service[attr_key]:
                    if is_valid_port(port) == False and is_valid_portrange(port) == False:
                        raise Exception(
                            "Port '{}' must be a valid port or port range".format(port))

    def add(self, name, **kwargs):
        if self.exists(name):
            raise ServiceExists("Service name already exists")

        for k in kwargs.keys():
            if k not in self.defaults.keys():
                raise ServiceNotValid(
                    "Invalid service parameter '{}'".format(k))

        service = self.defaults.copy()
        service.update(kwargs)

        # validate service
        try:
            self.validate(service)
        except Exception as e:
            raise ServiceNotValid(e.message)

        self._services[name] = service
        self._rule_deps[name] = []

    def update(self, name, **kwargs):
        if not self.exists(name):
            raise ServiceNotFound("Service not found")

        if self.is_reserved(name):
            raise ServiceNotValid(
                "Service cannot be altered as it is reserved")

        allowed_keys = self.defaults.keys()
        for k in kwargs.keys():
            if k not in allowed_keys:
                raise ServiceNotValid(
                    "Unrecognized service parameter '{}'".format(k))

        service = self._services[name].copy()
        service.update(kwargs)

        try:
            self.validate(service)
        except Exception as e:
            raise ServiceNotValid(e.message)

        if self._services[name] == service:
            raise ServiceNotUpdated("No changes detected")

        # update the service
        self._services[name] = service

    def delete(self, name):
        if not self.exists(name):
            raise ServiceNotFound("Service not found")

        if self.is_reserved(name):
            raise ServiceNotValid(
                "Service cannot be deleted as it is reserved")

        if len(self._rule_deps[name]) > 0:
            raise ServiceInUse(
                "Service cannot be deleted as some rules are currently using it", deps=self._rule_deps[name])

        del self._services[name]
        del self._rule_deps[name]

    def lookup(self, name, recurse=True):
        try:
            return self._services[name]
        except KeyError:
            raise ServiceNotFound("Service not found")

    def exists(self, service):
        try:
            self._services[service]
        except KeyError:
            return False

        return True

    def add_dep(self, service, rule):
        if not self.exists(service):
            raise ServiceNotFound("Service has not been defined")

        if rule not in self._rule_deps[service]:
            self._rule_deps[service].append(rule)

    def delete_dep(self, service, rule):
        if not self.exists(service):
            raise ServiceNotFound("Service has not been defined")

        if rule in self._rule_deps[service]:
            self._rule_deps[service].remove(rule)
