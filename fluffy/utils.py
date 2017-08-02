import re
import yaml
from collections import OrderedDict


def is_valid_port(port):
    if isinstance(port, int):
        return True if port > 0 and port < 65536 else False

    return False


def is_valid_portrange(portrange):
    if isinstance(portrange, basestring):
        if re.match(r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$', portrange):
            return True

    return False


def is_valid_cidr(cidr):
    if isinstance(cidr, basestring):
        if re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?$', cidr):
            return True

    return False


def is_valid_iprange(iprange):
    if isinstance(iprange, basestring):
        if re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', iprange):
            return True

    return False


def flatten(items, ret=None):
    if ret is None:
        ret = []

    for item in items:
        if isinstance(item, list):
            flatten(item, ret)
        else:
            ret.append(item)

    return ret


def ordered_load(stream, Loader=yaml.Loader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return yaml.load(stream, OrderedLoader)


def ordered_dump(data, stream=None, Dumper=yaml.Dumper, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_mapping(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, data.items())

    OrderedDumper.add_representer(OrderedDict, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


def boolify(v):
    if isinstance(v, bool):
        return v
    elif isinstance(v, basestring) and v.lower() in ['true', 'false']:
        return True if v.lower() == 'true' else False
    else:
        raise ValueError("Cannot convert string to boolean")
