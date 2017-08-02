import json
import logging
from flask import current_app
from flask import Blueprint, Response, jsonify, make_response, request
from flask_api import status
from flasgger import swag_from
from collections import OrderedDict

from ..common import session_exists
from ...exceptions import *
from ...application import fw, swagger
from ...utils import boolify

app = Blueprint('v1', __name__)


@app.route('/addressbook', methods=['GET'])
@swag_from('apidocs/addressbook.yaml')
def addressbook():
    try:
        recurse = boolify(request.args.get('recurse', False))
        return jsonify(dict(fw.addressbook.get(recurse=recurse)))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve the active addressbook', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/addressbook/<address_name>', methods=['GET'])
@swag_from('apidocs/addressbook_get.yaml')
def addressbook_get(address_name):
    try:
        recurse = boolify(request.args.get('recurse', False))
        return jsonify(dict(fw.addressbook.lookup(address_name, recurse=recurse)))
    except AddressNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup address', error=e.message), http_code)


@app.route('/sessions/<session_name>/addressbook', methods=['GET'])
@session_exists
@swag_from('apidocs/session_addressbook.yaml')
def session_addressbook(session_name):
    try:
        recurse = request.args.get('recurse', False)
        return jsonify(dict(fw.sessions[session_name].addressbook.get(recurse=recurse)))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session addressbook', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/addressbook/<address_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_addressbook_get.yaml')
def session_addressbook_get(session_name, address_name):
    try:
        recurse = boolify(request.args.get('recurse', False))
        return jsonify(dict(fw.sessions[session_name].addressbook.lookup(address_name, recurse=recurse)))
    except AddressNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup address', error=e.message), http_code)


@app.route('/sessions/<session_name>/addressbook/<address_name>', methods=['POST'])
@session_exists
@swag_from('apidocs/session_addressbook_add.yaml')
def session_addressbook_add(session_name, address_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].addressbook.add(
            name=address_name, **req)
        return make_response(jsonify(message='Address created'), status.HTTP_201_CREATED)
    except AddressExists as e:
        http_code = status.HTTP_409_CONFLICT
    except AddressNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create address', error=e.message), http_code)


@app.route('/sessions/<session_name>/addressbook/<address_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_addressbook_delete.yaml')
def session_addressbook_delete(session_name, address_name):
    data = {}
    try:
        fw.sessions[session_name].addressbook.delete(name=address_name)
        return make_response(jsonify(message='Address deleted'), status.HTTP_200_OK)
    except AddressNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except AddressInUse as e:
        http_code = status.HTTP_406_NOT_ACCEPTABLE
        data['deps'] = e.deps
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to delete address', error=e.message, **data), http_code)


@app.route('/sessions/<session_name>/addressbook/<address_name>', methods=['PATCH'])
@session_exists
@swag_from('apidocs/session_addressbook_update.yaml')
def session_addressbook_update(session_name, address_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].addressbook.update(
            name=address_name, **req)
        return make_response(jsonify(message='Address updated'), status.HTTP_200_OK)
    except AddressNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except AddressNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except AddressNotUpdated as e:
        return make_response(jsonify(message='Address not updated'), status.HTTP_204_NO_CONTENT)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to update address', error=e.message), http_code)


@app.route('/services', methods=['GET'])
@swag_from('apidocs/services.yaml')
def services():
    try:
        return jsonify(dict(fw.services))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve active services', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/services/<service_name>', methods=['GET'])
@swag_from('apidocs/service_get.yaml')
def service_get(service_name):
    try:
        return jsonify(fw.services[service_name])
    except ServiceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup service', error=e.message), http_code)


@app.route('/sessions/<session_name>/services', methods=['GET'])
@session_exists
@swag_from('apidocs/session_services.yaml')
def session_services(session_name):
    try:
        return jsonify(dict(fw.sessions[session_name].services))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session services', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/services/<service_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_service_get.yaml')
def session_service_get(session_name, service_name):
    try:
        return jsonify(fw.sessions[session_name].services[service_name])
    except ServiceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup service', error=e.message), http_code)


@app.route('/sessions/<session_name>/services/<service_name>', methods=['POST'])
@session_exists
@swag_from('apidocs/session_service_add.yaml')
def session_service_add(session_name, service_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].services.add(name=service_name, **req)
        return make_response(jsonify(message='Service created'), status.HTTP_201_CREATED)
    except ServiceExists as e:
        http_code = status.HTTP_409_CONFLICT
    except ServiceNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create service', error=e.message), http_code)


@app.route('/sessions/<session_name>/services/<service_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_service_delete.yaml')
def session_service_delete(session_name, service_name):
    data = {}

    try:
        fw.sessions[session_name].services.delete(name=service_name)
        return make_response(jsonify(message='Service deleted'), status.HTTP_200_OK)
    except ServiceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except ServiceInUse as e:
        http_code = status.HTTP_406_NOT_ACCEPTABLE
        data['deps'] = e.deps
    except ServiceNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to delete service', error=e.message, **data), http_code)


@app.route('/sessions/<session_name>/services/<service_name>', methods=['PATCH'])
@session_exists
@swag_from('apidocs/session_service_update.yaml')
def session_service_update(session_name, service_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].services.update(
            name=service_name, **req)
        return make_response(jsonify(message='Service updated'), status.HTTP_200_OK)
    except ServiceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except ServiceNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except ServiceNotUpdated as e:
        return make_response(jsonify(message='Service not updated'), status.HTTP_204_NO_CONTENT)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to update service', error=e.message), http_code)


@app.route('/chains', methods=['GET'])
@swag_from('apidocs/chains.yaml')
def chains():
    try:
        return jsonify(dict(fw.chains))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve active chains', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/chains/<table_name>/<chain_name>', methods=['GET'])
@swag_from('apidocs/chain_get.yaml')
def chain_get(table_name, chain_name):
    try:
        return jsonify(fw.chains.lookup(name=chain_name, table=table_name))
    except ChainNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup chain', error=e.message), http_code)


@app.route('/sessions/<session_name>/chains', methods=['GET'])
@session_exists
@swag_from('apidocs/session_chains.yaml')
def session_chains(session_name):
    try:
        return jsonify(dict(fw.sessions[session_name].chains))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session chains', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/chains/<table_name>/<chain_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_chain_get.yaml')
def session_chain_get(session_name, table_name, chain_name):
    try:
        return jsonify(fw.sessions[session_name].chains.lookup(name=chain_name, table=table_name))
    except ChainNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup chain', error=e.message), http_code)


@app.route('/sessions/<session_name>/chains/<table_name>/<chain_name>', methods=['POST'])
@session_exists
@swag_from('apidocs/session_chain_add.yaml')
def session_chain_add(session_name, table_name, chain_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].chains.add(
            name=chain_name, table=table_name, **req)
        return make_response(jsonify(message='Chain created'), status.HTTP_201_CREATED)
    except ChainExists as e:
        http_code = status.HTTP_409_CONFLICT
    except ChainNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create chain', error=e.message), http_code)


@app.route('/sessions/<session_name>/chains/<table_name>/<chain_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_chain_delete.yaml')
def session_chain_delete(session_name, table_name, chain_name):
    data = {}

    try:
        fw.sessions[session_name].chains.delete(
            name=chain_name, table=table_name)
        return make_response(jsonify(message='Chain deleted'), status.HTTP_200_OK)
    except ChainNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except ChainInUse as e:
        http_code = status.HTTP_406_NOT_ACCEPTABLE
        data['deps'] = e.deps
    except ChainNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to delete chain', error=e.message, **data), http_code)


@app.route('/sessions/<session_name>/chains/<table_name>/<chain_name>', methods=['PATCH'])
@session_exists
@swag_from('apidocs/session_chain_update.yaml')
def session_chain_update(session_name, table_name, chain_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].chains.update(
            name=chain_name, table=table_name, **req)
        return make_response(jsonify(message='Chain updated'), status.HTTP_200_OK)
    except ChainNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except ChainNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except ChainNotUpdated as e:
        return make_response(jsonify(message='Chain not updated'), status.HTTP_204_NO_CONTENT)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to update chain', error=e.message), http_code)


@app.route('/interfaces', methods=['GET'])
@swag_from('apidocs/interfaces.yaml')
def interfaces():
    try:
        return jsonify(dict(fw.interfaces))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve active interfaces', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/interfaces/<interface_name>', methods=['GET'])
@swag_from('apidocs/interface_get.yaml')
def interface_get(interface_name):
    try:
        return jsonify(fw.interfaces[interface_name])
    except InterfaceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup interface', error=e.message), http_code)


@app.route('/sessions/<session_name>/interfaces', methods=['GET'])
@session_exists
@swag_from('apidocs/session_interfaces.yaml')
def session_interfaces(session_name):
    try:
        return jsonify(dict(fw.sessions[session_name].interfaces))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session interfaces', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/interfaces/<interface_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_interface_get.yaml')
def session_interface_get(session_name, interface_name):
    try:
        return jsonify(fw.sessions[session_name].interfaces[interface_name])
    except InterfaceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup interface', error=e.message), http_code)


@app.route('/sessions/<session_name>/interfaces/<interface_name>', methods=['POST'])
@session_exists
@swag_from('apidocs/session_interface_add.yaml')
def session_interface_add(session_name, interface_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].interfaces.add(
            name=interface_name, **req)
        return make_response(jsonify(message='Interface created'), status.HTTP_201_CREATED)
    except InterfaceExists as e:
        http_code = status.HTTP_409_CONFLICT
    except InterfaceNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create interface', error=e.message), http_code)


@app.route('/sessions/<session_name>/interfaces/<interface_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_interface_delete.yaml')
def session_interface_delete(session_name, interface_name):
    data = {}

    try:
        fw.sessions[session_name].interfaces.delete(name=interface_name)
        return make_response(jsonify(message='Interface deleted'), status.HTTP_200_OK)
    except InterfaceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except InterfaceInUse as e:
        http_code = status.HTTP_406_NOT_ACCEPTABLE
        data['deps'] = e.deps
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to delete interface', error=e.message, **data), http_code)


@app.route('/sessions/<session_name>/interfaces/<interface_name>', methods=['PATCH'])
@session_exists
@swag_from('apidocs/session_interface_update.yaml')
def session_interface_update(session_name, interface_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].interfaces.update(name=interface_name, **req)
        return make_response(jsonify(message='Interface updated'), status.HTTP_200_OK)
    except InterfaceNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except InterfaceNotUpdated as e:
        return make_response(jsonify(message='Interface not updated'), status.HTTP_204_NO_CONTENT)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to update interface', error=e.message), http_code)


@app.route('/rules', methods=['GET'])
@swag_from('apidocs/rules.yaml')
def rules():
    try:
        return make_response(json.dumps(OrderedDict(fw.rules), indent=2, separators=(', ', ': ')), status.HTTP_200_OK)
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve active rules', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/rules/<rule_name>', methods=['GET'])
@swag_from('apidocs/rule_get.yaml')
def rule_get(rule_name):
    try:
        return jsonify(fw.rules[rule_name])
    except RuleNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup rule', error=e.message), http_code)


@app.route('/sessions/<session_name>/rules', methods=['GET'])
@session_exists
@swag_from('apidocs/session_rules.yaml')
def session_rules(session_name):
    try:
        return make_response(json.dumps(OrderedDict(fw.sessions[session_name].rules), indent=2, separators=(', ', ': ')), status.HTTP_200_OK)
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session rules', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/rules/<rule_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_rule_get.yaml')
def session_rule_get(session_name, rule_name):
    try:
        return jsonify(fw.sessions[session_name].rules[rule_name])
    except RuleNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup rule', error=e.message), http_code)


@app.route('/sessions/<session_name>/rules/<rule_name>', methods=['POST'])
@session_exists
@swag_from('apidocs/session_rule_add.yaml')
def session_rule_add(session_name, rule_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].rules.add(name=rule_name, **req)
        return make_response(jsonify(message='Rule created'), status.HTTP_201_CREATED)
    except RuleExists as e:
        http_code = status.HTTP_409_CONFLICT
    except RuleNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create rule', error=e.message), http_code)


@app.route('/sessions/<session_name>/rules/<rule_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_rule_delete.yaml')
def session_rule_delete(session_name, rule_name):
    try:
        fw.sessions[session_name].rules.delete(name=rule_name)
        return make_response(jsonify(message='Rule deleted'), status.HTTP_200_OK)
    except RuleNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to delete rule', error=e.message), http_code)


@app.route('/sessions/<session_name>/rules/<rule_name>', methods=['PATCH'])
@session_exists
@swag_from('apidocs/session_rule_update.yaml')
def session_rule_update(session_name, rule_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].rules.update(name=rule_name, **req)
        return make_response(jsonify(message='Rule updated'), status.HTTP_200_OK)
    except RuleNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except RuleNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except RuleNotUpdated as e:
        return make_response(jsonify(message='Rule not updated'), status.HTTP_204_NO_CONTENT)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to update rule', error=e.message), http_code)


@app.route('/sessions', methods=['GET'])
@swag_from('apidocs/sessions.yaml')
def sessions():
    try:
        return jsonify(dict(fw.sessions))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve active sessions', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>', methods=['POST'])
@swag_from('apidocs/session_add.yaml')
def session_add(session_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}

        fw.sessions.add(name=session_name, **req)
        return make_response(jsonify(message='Session created'), status.HTTP_201_CREATED)
    except SessionExists as e:
        http_code = status.HTTP_409_CONFLICT
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create session', error=e.message), http_code)


@app.route('/sessions/<session_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_get.yaml')
def session_get(session_name):
    try:
        return make_response(jsonify(fw.sessions[session_name].status()), status.HTTP_200_OK)
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_delete.yaml')
def session_delete(session_name):
    try:
        fw.sessions.delete(session_name)
        return make_response(jsonify(message='Session deleted'), status.HTTP_200_OK)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return make_response(jsonify(message='Failed to delete session', error=e.message), http_code)


@app.route('/sessions/<session_name>/test', methods=['POST'])
@session_exists
@swag_from('apidocs/session_test.yaml')
def session_test(session_name):
    try:
        ok, err = fw.sessions[session_name].test()
        if ok:
            return make_response(jsonify(message='Configuration test passed'), status.HTTP_200_OK)
        else:
            return make_response(jsonify(message='Configuration test failed', error=err), status.HTTP_412_PRECONDITION_FAILED)
    except Exception as e:
        return make_response(jsonify(message='Configuration test failed', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/commit', methods=['POST'])
@session_exists
@swag_from('apidocs/session_commit.yaml')
def session_commit(session_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].commit(async=True, **req)
        return make_response(jsonify(message='Configuration committed - status can be checked by GET /sessions/{}'.format(session_name)), status.HTTP_200_OK)
    except Exception as e:
        return make_response(jsonify(message='Failed to commit configuration', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/confirm', methods=['POST'])
@session_exists
@swag_from('apidocs/session_confirm.yaml')
def session_confirm(session_name):
    try:
        fw.sessions[session_name].confirm()
        return make_response(jsonify(message='Configuration successfully confirmed'), status.HTTP_200_OK)
    except Exception as e:
        return make_response(jsonify(message='Failed to confirm configuration', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/checks', methods=['GET'])
@swag_from('apidocs/checks.yaml')
def checks():
    try:
        return jsonify(dict(fw.checks))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve rollback checks', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/checks/<check_name>', methods=['GET'])
@swag_from('apidocs/check_get.yaml')
def check_get(check_name):
    try:
        return jsonify(fw.checks[check_name])
    except CheckNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup rollback check', error=e.message), http_code)


@app.route('/sessions/<session_name>/checks', methods=['GET'])
@session_exists
@swag_from('apidocs/session_checks.yaml')
def session_checks(session_name):
    try:
        return jsonify(dict(fw.sessions[session_name].checks))
    except Exception as e:
        return make_response(jsonify(message='Failed to retrieve session rollback checks', error=e.message), status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.route('/sessions/<session_name>/checks/<check_name>', methods=['GET'])
@session_exists
@swag_from('apidocs/session_check_get.yaml')
def session_check_get(session_name, check_name):
    try:
        return jsonify(fw.sessions[session_name].checks[check_name])
    except CheckNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to lookup rollback check', error=e.message), http_code)


@app.route('/sessions/<session_name>/checks/<check_name>', methods=['POST'])
@session_exists
@swag_from('apidocs/session_check_add.yaml')
def session_check_add(session_name, check_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].checks.add(check_name, **req)
        return make_response(jsonify(message='Rollback check created'), status.HTTP_201_CREATED)
    except CheckExists as e:
        http_code = status.HTTP_409_CONFLICT
    except CheckNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to create rollback check', error=e.message), http_code)


@app.route('/sessions/<session_name>/checks/<check_name>', methods=['DELETE'])
@session_exists
@swag_from('apidocs/session_check_delete.yaml')
def session_check_delete(session_name, check_name):
    try:
        fw.sessions[session_name].checks.delete(check_name)
        return make_response(jsonify(message='Rollback check deleted'), status.HTTP_200_OK)
    except CheckNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to delete rollback check', error=e.message), http_code)


@app.route('/sessions/<session_name>/checks/<check_name>', methods=['PATCH'])
@session_exists
@swag_from('apidocs/session_check_update.yaml')
def session_check_update(session_name, check_name):
    try:
        req = request.get_json()
        if req is None:
            req = {}
        fw.sessions[session_name].checks.update(name=check_name, **req)
        return make_response(jsonify(message='Rollback check updated'), status.HTTP_200_OK)
    except CheckNotFound as e:
        http_code = status.HTTP_404_NOT_FOUND
    except CheckNotValid as e:
        http_code = status.HTTP_400_BAD_REQUEST
    except CheckNotUpdated as e:
        return make_response(jsonify(message='Rollback check not updated'), status.HTTP_204_NO_CONTENT)
    except Exception as e:
        http_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return make_response(jsonify(message='Failed to update rollback check', error=e.message), http_code)
