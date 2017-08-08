import sys
import logging
import glob
import os
import re
import subprocess
import tempfile
import yaml
import shutil
from collections import OrderedDict

import logging
logger = logging.getLogger(__name__)

from .exceptions import *
from .utils import *


class Rules(object):
    """This class implements the Fluffy rules"""

    defaults = {
        'table': 'filter',
        'chain': None,
        'action': None,
        'jump': None,
        'negate_protocol': False,
        'protocol': [],
        'negate_icmp_type': False,
        'icmp_type': None,
        'negate_tcp_flags': False,
        'tcp_flags': None,
        'negate_ctstate': False,
        'ctstate': [],
        'negate_state': False,
        'state': [],
        'negate_src_address_range': False,
        'src_address_range': [],
        'negate_dst_address_range': False,
        'dst_address_range': [],
        'negate_in_interface': False,
        'in_interface': [],
        'negate_out_interface': False,
        'out_interface': [],
        'negate_src_address': False,
        'src_address': [],
        'negate_dst_address': False,
        'dst_address': [],
        'negate_src_service': False,
        'negate_dst_service': False,
        'src_service': [],
        'dst_service': [],
        'reject_with': None,
        'set_mss': None,
        'clamp_mss_to_pmtu': False,
        'to_src': None,
        'to_dst': None,
        'limit': None,
        'limit_burst': None,
        'log_prefix': None,
        'log_level': None,
        'comment': None
    }
    """dict: Default rule configuration"""

    def __init__(self, rules, db, addressbook=None, interfaces=None, chains=None, services=None):
        """Initialize an instance of the Rules class

        Args:
            services (dict): A dictionary describing the rules
            db (str): Location to the rules database

        """

        self.addressbook = addressbook
        """AddressBook: Reference to the addressbook"""

        self.interfaces = interfaces
        """Interfaces: Reference to the interfaces"""

        self.chains = chains
        """Chains: Reference to the chains"""

        self.services = services
        """Services: Reference to the services"""

        self._rules = {}
        """dict: The rule entries"""

        self._rules_with_index = []
        """list: Keep track of rules order"""

        for name, rule in rules.iteritems():
            self.add(name=name, index=None, **rule)

        self._db = db
        """str: The rules database location"""

    def __getitem__(self, key):
        """Retrieve a rule

        Args:
            key (str): The rule to lookup

        Returns:
            dict: The looked up rule

        """

        return self.lookup(key)

    def __iter__(self):
        """Retrieve all rules

        Returns:
            iterator: The rules

        """

        for index, name in enumerate(self._rules_with_index):
            yield name, dict(self._rules[name].items() + {'index': index}.items())

    def update_objref(self, obj):
        """Update the rules

        Args:
            obj (Rules): The rules object

        """

        self._rules = obj.rules()
        self._rules_with_index = obj.rules_with_index()

    def rules(self):
        """Retrieve the rules as a dictionary

        Returns:
            dict: The rules

        """

        return self._rules

    def rules_with_index(self):
        """Retrieve the rules as a list

        Returns:
            list: The rules

        """

        return self._rules_with_index

    def save(self):
        """Persist the rules to disk"""

        try:
            logger.debug("Backing up rules")
            if os.path.exists(self._db):
                shutil.copyfile(self._db, "{}.bak".format(self._db))
        except Exception as e:
            logger.exception("Failed to backup rules")
            return

        try:
            logger.debug("Saving rules")
            with open(self._db, 'w') as f:
                f.write(ordered_dump(OrderedDict(
                    ((k, self._rules[k]) for k in self._rules_with_index)), Dumper=yaml.SafeDumper, default_flow_style=False, explicit_start=True))
        except:
            logger.exception("Failed to save rules")

    def add(self, name, index=None, **kwargs):
        """Add a new rule

        Args:
            name (str): The rule name
            index (Optional[int]): The rule index
            **kwargs: Arbitrary keyword arguments

        Raises:
            RuleExists, RuleNotValid

        """

        if self.exists(name):
            raise RuleExists("Rule already exists")

        defaults = self.defaults

        for k in kwargs.keys():
            if k not in defaults.keys():
                raise RuleNotValid(
                    "Unrecognized rule parameter '{}'".format(k))

        rule = defaults.copy()
        rule.update(kwargs)

        # Rule netfilter table
        if rule['table']:
            rule['table'] = rule['table'].lower()
            if rule['table'] not in ['filter', 'nat', 'mangle', 'raw', 'security']:
                raise RuleNotValid("Invalid packet matching table")
        else:
            raise RuleNotValid("Rule packet matching table is required")

        # Rule chain
        if rule['chain']:
            rule['chain'] = rule['chain'].upper()
            if not self.chains.exists(name=rule['chain'], table=rule['table']):
                raise RuleNotValid("Rule chain not found")
        else:
            raise RuleNotValid("Rule chain is required")

        # validate rule
        try:
            self.validate(rule)
        except Exception as e:
            raise RuleNotValid(e.message)

        if index:
            if index < 0 or index > len(self._rules_with_index):
                raise RuleNotValid("Rule index is out of range")
        else:
            index = len(self._rules_with_index)

        self._rules_with_index.insert(index, name)
        self._rules[name] = rule

        # manage dependencies here
        for attr_key in ['in_interface', 'out_interface']:
            for interface in rule[attr_key]:
                self.interfaces.add_dep(interface=interface, rule=name)

        for attr_key in ['src_address_range', 'dst_address_range', 'src_address', 'dst_address']:
            if rule[attr_key]:
                for addr in rule[attr_key]:
                    self.addressbook.add_dep(address=addr, rule=name)

        for attr_key in ['jump', 'chain']:
            if rule[attr_key]:
                self.chains.add_dep(
                    table=rule['table'], chain=rule[attr_key], rule=name)

        for attr_key in ['src_service', 'dst_service']:
            if rule[attr_key]:
                for srv in rule[attr_key]:
                    self.services.add_dep(service=srv, rule=name)

    def update(self, name, index=None, **kwargs):
        """Update a rule

        Args:
            name (str): The rule name
            index (Optional[int]): The rule index
            **kwargs: Arbitrary keyword arguments

        Raises:
            RuleNotFound, RuleNotValid, RuleNotUpdated

        """

        if not self.exists(name):
            raise RuleNotFound("Rule not found")

        allowed_keys = list(set(self.defaults) - set(['chain', 'table']))

        for k in kwargs.keys():
            if k not in allowed_keys:
                raise RuleNotValid(
                    "Unrecognized rule parameter '{}'".format(k))

        rule = self._rules[name].copy()
        rule.update(kwargs)

        # validate rule
        try:
            self.validate(rule)
        except Exception as e:
            raise RuleNotValid(e.message)

        if index:
            if index < 0 or index > len(self._rules_with_index):
                raise RuleNotValid("Rule index is out of range")

            if self._rules[name] == rule and self._rules_with_index[index] == name:
                raise RuleNotUpdated("No changes detected")

            if self._rules_with_index[index] != name:
                self._rules_with_index.remove(name)
                self._rules_with_index.insert(index, name)
        else:
            if self._rules[name] == rule:
                raise RuleNotUpdated("No changes detected")

        # manage dependencies here
        if self._rules[name] != rule:
            for attr_key in ['in_interface', 'out_interface']:
                for interface in list(set(self._rules[name][attr_key]) - set(rule[attr_key])):
                    self.interfaces.delete_dep(interface=interface, rule=name)

                for interface in list(set(rule[attr_key]) - set(self._rules[name][attr_key])):
                    self.interfaces.add_dep(interface=interface, rule=name)

            for attr_key in ['src_address_range', 'dst_address_range', 'src_address', 'dst_address']:
                for addr in list(set(self._rules[name][attr_key]) - set(rule[attr_key])):
                    self.addressbook.delete_dep(address=addr, rule=name)

                for addr in list(set(rule[attr_key]) - set(self._rules[name][attr_key])):
                    self.addressbook.add_dep(address=addr, rule=name)

            for attr_key in ['jump', 'chain']:
                if self._rules[name][attr_key] != rule[attr_key]:
                    self.chains.delete_dep(
                        table=rule['table'], chain=self._rules[name][attr_key], rule=name)
                    self.chains.add_dep(
                        table=rule['table'], chain=rule[attr_key], rule=name)

            for attr_key in ['src_service', 'dst_service']:
                for srv in list(set(self._rules[name][attr_key]) - set(rule[attr_key])):
                    self.services.delete_dep(service=srv, rule=name)

                for srv in list(set(rule[attr_key]) - set(self._rules[name][attr_key])):
                    self.services.add_dep(service=srv, rule=name)

            self._rules[name].update(rule)

    def delete(self, name):
        """Delete a rule

        Args:
            name (str): The rule name

        Raises:
            RuleNotFound, RuleInUse, RuleNotValid

        """

        if not self.exists(name):
            raise RuleNotFound("Rule not found")

        # manage dependencies here
        for attr_key in ['in_interface', 'out_interface']:
            for interface in self._rules[name][attr_key]:
                self.interfaces.delete_dep(interface=interface, rule=name)

        for attr_key in ['src_address_range', 'dst_address_range', 'src_address', 'dst_address']:
            if self._rules[name][attr_key]:
                for addr in self._rules[name][attr_key]:
                    self.addressbook.delete_dep(address=addr, rule=name)

        for attr_key in ['jump', 'chain']:
            if self._rules[name][attr_key]:
                self.chains.delete_dep(
                    table=self._rules[name]['table'], chain=self._rules[name][attr_key], rule=name)

        for attr_key in ['src_service', 'dst_service']:
            for service in self._rules[name][attr_key]:
                self.services.delete_dep(service=service, rule=name)

        self._rules_with_index.remove(name)
        del self._rules[name]

    def exists(self, name):
        """Returns whether a rule exists or not

        Args:
            name (str): The rule

        Returns:
            bool: True if the rule exists, else False

        """

        try:
            self.lookup(name)
        except RuleNotFound:
            return False

        return True

    def lookup(self, name):
        """Look up a rule

        Args:
            name (str): The rule

        Returns:
            dict: The looked up rule entry

        Raises:
            RuleNotFound

        """

        try:
            return self._rules[name]
        except KeyError:
            raise RuleNotFound("Rule not found")

    @classmethod
    def load_yaml(cls, db, addressbook, interfaces, chains, services):
        """Load the rules from the database

        Args:
            db (str): The rules database

        Returns:
            Services: An instance of the Rules class

        Raises:
            RuntimeError

        """

        rules = {}

        if os.path.exists(db):
            try:
                with open(db, 'r') as stream:
                    rules = ordered_load(stream)
            except Exception as e:
                raise RuntimeError(
                    "Failed to load rules ({})".format(e.message))

        return cls(rules=rules, db=db, addressbook=addressbook, interfaces=interfaces, chains=chains, services=services)

    def validate(self, rule):
        """Validate a rule configuration

        Args:
            rule (dict): The rule configuration

        """

        if (rule['action'] == None and rule['jump'] == None) or (rule['action'] and rule['jump']):
            raise Exception("Either action or jump are required")

        if rule['action']:
            rule['action'] = rule['action'].upper()
        else:
            rule['jump'] = rule['jump'].upper()

        # Rule action
        if rule['action']:
            if rule['action'] not in ['ACCEPT', 'DROP', 'REJECT', 'QUEUE', 'RETURN', 'DNAT', 'SNAT', 'LOG', 'MASQUERADE', 'REDIRECT', 'MARK', 'TCPMSS']:
                raise Exception("Invalid rule action")
        else:
            if rule['jump'] == rule['chain']:
                raise Exception(
                    "Rule jump cannot be the same as the rule chain")

            if not self.chains.exists(name=rule['jump'], table=rule['table']):
                raise Exception("Rule jump does not match any chains")

        # The following options must be treated as lists
        for attr_key in ['protocol', 'ctstate', 'state', 'in_interface', 'out_interface', 'src_address_range', 'dst_address_range', 'src_address', 'dst_address', 'src_service', 'dst_service']:
            # Convert to list first
            if not isinstance(rule[attr_key], list):
                rule[attr_key] = [rule[attr_key]]

            # Unique elements and convert them to strings
            rule[attr_key] = list(set([str(i) for i in rule[attr_key]]))

        # Check if we have valid services
        if rule['protocol'] and (rule['src_service'] or rule['dst_service']):
            raise Exception(
                "Protocol and src_service/dst_service cannot be used together")

        protocol = []
        if rule['protocol']:
            if len(rule['protocol']) > 1 and 'any' in rule['protocol']:
                raise Exception("Cannot mix 'any' with other protocols")

            for proto in rule['protocol']:
                if proto not in ['ip', 'tcp', 'udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'vrrp', 'igmp', 'ipencap', 'ipv4', 'ipv6', 'ospf', 'gre', 'cbt', 'sctp', 'pim', 'any']:
                    raise Exception("Invalid rule protocol '{}'".format(proto))

            protocol = rule['protocol']
        else:
            service_proto = None
            for attr_key in [('src_service', 'src_port'), ('dst_service', 'dst_port')]:
                if rule[attr_key[0]]:
                    for service in rule[attr_key[0]]:
                        if not self.services.exists(service):
                            raise Exception(
                                "Service '{}' not found in services list".format(service))

                        # check if protocol is consistent
                        data_lookup = self.services.lookup(service)

                        if not data_lookup[attr_key[1]]:
                            raise Exception(
                                "Service '{}' has no {} defined".format(service, attr_key[1]))

                        if service_proto:
                            if service_proto != data_lookup['protocol']:
                                raise Exception(
                                    "Cannot mix services which have different protocols together")
                        else:
                            service_proto = data_lookup['protocol']

            if service_proto:
                protocol = [service_proto]

        # ICMP options
        if rule['icmp_type']:
            if len(protocol) != 1 or 'icmp' not in protocol:
                raise Exception(
                    "Rule protocol must be set to 'icmp' when using ICMP parameters")

            if rule['icmp_type'] not in ['any', 'echo-reply', 'destination-unreachable', 'network-unreachable', 'host-unreachable', 'protocol-unreachable', 'port-unreachable', 'fragmentation-needed', 'source-route-failed', 'network-unknown', 'host-unknown', 'network-prohibited', 'host-prohibited', 'TOS-network-unreachable', 'TOS-host-unreachable', 'communication-prohibited', 'host-precedence-violation', 'precedence-cutoff', 'source-quench', 'redirect', 'network-redirect', 'host-redirect', 'TOS-network-redirect', 'TOS-host-redirect', 'echo-request', 'router-advertisement', 'router-solicitation', 'time-exceeded', 'ttl-zero-during-transit', 'ttl-zero-during-reassembly', 'parameter-problem', 'ip-header-bad', 'required-option-missing', 'timestamp-request', 'timestamp-reply', 'address-mask-request', 'address-mask-reply']:
                raise Exception("Invalid ICMP type")

        # TCP options
        if rule['tcp_flags']:
            if len(protocol) != 1 and 'tcp' not in protocol:
                raise Exception(
                    "Rule protocol must be set to 'tcp' when using TCP options")

            if not re.match(r'^((SYN|ACK|FIN|RST|URG|PSH|ALL|NONE|,(?!\s))+\s(SYN|ACK|FIN|RST|URG|PSH|ALL|NONE|,(?!$)))', rule['tcp_flags']):
                raise Exception("Invalid TCP flags detected")

        # Conntrack state
        if rule['ctstate']:
            for state in rule['ctstate']:
                if state not in ['INVALID', 'NEW', 'ESTABLISHED', 'RELATED', 'UNTRACKED', 'SNAT', 'DNAT']:
                    raise Exception(
                        "Invalid conntrack state '{}'".format(state))

        if rule['state']:
            for state in rule['state']:
                if state not in ['INVALID', 'ESTABLISHED', 'NEW', 'RELATED']:
                    raise Exception("Invalid TCP state '{}'".format(state))

        # Check if we have valid addresses
        for attr_key in ['src_address_range', 'dst_address_range', 'src_address', 'dst_address']:
            if (attr_key == 'src_address' or attr_key == 'dst_address') and len(rule[attr_key]) > 1 and 'any' in rule[attr_key]:
                raise Exception("Cannot mix 'any' with other addresses")

            for addr in rule[attr_key]:
                if not self.addressbook.exists(addr):
                    raise Exception(
                        "Address '{}' not found in addressbook".format(addr))

                # is it a valid IP Range?
                if attr_key == 'src_address_range' or attr_key == 'dst_address_range':
                    for v in self.addressbook.lookup(addr, recurse=True):
                        if not is_valid_iprange(v):
                            raise Exception(
                                "Address '{}' is not a valid IP range".format(addr))

        # Check if we have valid interfaces
        for attr_key in ['in_interface', 'out_interface']:
            for interface in rule[attr_key]:
                if not self.interfaces.exists(interface):
                    raise Exception(
                        "Interface '{}' not found".format(interface))

            if len(rule[attr_key]) > 1 and 'any' in rule[attr_key]:
                raise Exception("Cannot mix 'any' with other interfaces")

        # make sure input and output interfaces do not share any interfaces
        if bool((set(rule['in_interface']) - set(['any'])) & (set(rule['out_interface']) - set(['any']))):
            raise Exception("Input and output interfaces cannot be the same")

        if self.chains.is_builtin(name=rule['chain'], table=rule['table']):
            if rule['in_interface'] and rule['chain'] not in ['INPUT', 'FORWARD', 'PREROUTING']:
                raise Exception(
                    "Input interface can only be used with INPUT, FORWARD, and PREROUTING built-in chains")

            if not rule['in_interface'] and rule['chain'] in ['INPUT', 'FORWARD', 'PREROUTING']:
                raise Exception(
                    "Input interface is required for INPUT, FORWARD, and PREROUTING built-in chains")

            if rule['out_interface'] and rule['chain'] not in ['OUTPUT', 'FORWARD', 'POSTROUTING']:
                raise Exception(
                    "Output interface can only be used with OUTPUT, FORWARD, and POSTROUTING built-in chains")

            if not rule['out_interface'] and rule['chain'] in ['OUTPUT', 'FORWARD', 'POSTROUTING']:
                raise Exception(
                    "Output interface is required for OUTPUT, FORWARD, and POSTROUTING built-in chains")

        # ICMP rejection
        if rule['reject_with']:
            if rule['action'] != 'REJECT':
                raise Exception(
                    "Rule action must be set to 'REJECT' when using reject_with")

            if rule['reject_with'] not in ['icmp-net-unreachable', 'icmp-host-unreachable', 'icmp-port-unreachable', 'icmp-proto-unreachable', 'icmp-net-prohibited', 'icmp-host-prohibited', 'icmp-admin-prohibited']:
                raise Exception("Not a valid reject with parameter")

        # Destination NAT
        if rule['to_dst']:
            if rule['action'] != 'DNAT':
                raise Exception(
                    "Rule action must be set to 'DNAT' when using to_dst")

            if rule['table'] != 'nat':
                raise Exception(
                    "Rule packet matching table must be 'nat' when using destination NAT")

        # Source NAT
        if rule['to_src']:
            if rule['action'] != 'SNAT':
                raise Exception(
                    "Rule action must be set to 'SNAT' when using to_src")

            if rule['table'] != 'nat':
                raise Exception(
                    "Rule packet matching table must be 'nat' when using source NAT")

        # MSS clamping
        if rule['set_mss'] and rule['clamp_mss_to_pmtu']:
            raise Exception("Either set_mss or clamp_mss_to_pmtu can be used")

        if rule['set_mss'] or rule['clamp_mss_to_pmtu']:
            if rule['action'] != 'TCPMSS':
                raise Exception(
                    "Rule action must be set to 'TCPMSS' when using MSS clamping")

        # Logging
        if rule['log_prefix'] or rule['log_level']:
            if rule['action'] != 'LOG':
                raise Exception(
                    "Rule action must be set to 'LOG' when using log options")

            if rule['log_level']:
                if rule['log_level'] not in ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']:
                    raise Exception("Invalid rule log level")

        # Validate booleans
        for k, v in self.defaults.iteritems():
            if isinstance(v, bool) and not isinstance(rule[k], bool):
                raise Exception(
                    "Rule parameter '{}' must be type bool".format(k))

