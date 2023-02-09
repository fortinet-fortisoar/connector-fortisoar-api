import requests
import json
from cshmac.requests import HmacAuth
from connectors.core.connector import get_logger, ConnectorError
from .constants import LOGGER_NAME

logger = get_logger(LOGGER_NAME)


def invoke_rest_endpoint(config, endpoint, method='GET', data=None, headers=None):
    server_address = get_server_address(config)
    full_uri = 'https://{server_address}{endpoint}'.format(server_address=server_address, endpoint=endpoint)
    auth_type = config.get('auth_type')
    verify_ssl = config.get('verify_ssl', True)
    if headers is None:
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

    if method.lower() == "GET":
        data = None

    if (auth_type == 'Basic'):
        token = login_using_basic_auth(config)
        headers["Authorization"] = "Bearer " + token
    elif (auth_type == 'HMAC'):
        hmac_auth = generate_hmac(config, full_uri, method, json.dumps(data))
    else:
        logger.exception('Invalid authentication type: {0}'.format(auth_type))
        raise ConnectorError('Invalid authentication type: {0}'.format(auth_type))
    
    try:
        if (auth_type == 'Basic'):
            response = requests.request(method, full_uri, verify=verify_ssl, json=data, headers=headers)
        else:
            if data:
                response = requests.request(method, full_uri, auth=hmac_auth, verify=verify_ssl, headers=headers, json=data)
            else:
                response = requests.request(method, full_uri, auth=hmac_auth, verify=verify_ssl, headers=headers)
    except Exception as e:
        logger.exception('Error invoking endpoint: {0}'.format(full_uri))
        raise ConnectorError('Error: {0}'.format(str(e)))
    return maybe_json_or_raise(response)


def login(config):
    auth_type = config.get('auth_type')
    if auth_type == 'Basic':
        return login_using_basic_auth(config)
    else:
        return login_using_hmac_auth(config)

      
def login_using_basic_auth(config):
    server_address = get_server_address(config)
    username = config.get('username')
    password = config.get('password')
    verify_ssl = config.get('verify_ssl', True)
    headers = {'Content-Type': 'application/json'}
    if not server_address or not username or not password:
        raise ConnectorError('Missing required parameters')
    
    auth_url = 'https://{server_address}/auth/authenticate'.format(server_address=server_address)
    auth_payload = {
        "credentials": {
            "loginid": username,
            "password": password
        }
    }

    try:
        response = requests.request('POST', auth_url, verify=verify_ssl, json=auth_payload, headers=headers)
    except Exception as e:
        logger.exception('Error invoking endpoint: {0}'.format(auth_url))
        raise ConnectorError('Error: {0}'.format(str(e)))
    if response.ok:
        data = response.json()
        return data.get('token')
    else:
        logger.error(response.content)
        raise ConnectorError(response.content)


def login_using_hmac_auth(config, payload=None):
    server_address = get_server_address(config)
    verify_ssl = config.get('verify_ssl', True)
    
    # Full URI to authenticate HMAC and connection to the remote FortiSOAR
    full_uri = 'https://{server_address}/api/auth/license/?param=license_details'.format(server_address=server_address)
    try:
        hmac_auth = generate_hmac(config, full_uri, 'GET', payload)
        response = requests.request('GET', full_uri, auth=hmac_auth, verify=verify_ssl, json=payload)
    except Exception as e:
        logger.exception('Error invoking endpoint: {0}'.format(full_uri))
        raise ConnectorError('Error: {0}'.format(str(e)))
    
    if response.ok:
        return response.json()
    else:
        logger.error("HMAC authentication failed")
        raise ConnectorError("HMAC authentication failed")


def generate_hmac(config, full_uri, method, payload):
    public_key = format_keys(config.get('public_key').strip())
    private_key = format_keys(config.get('private_key').strip())
    
    if method == 'GET':
        payload = public_key
    return HmacAuth(full_uri, method, public_key, private_key, payload)


def format_keys(input_key):
    content = input_key.split('-----')
    content[2] = content[2].replace(' ', '\n')
    input_key = '-----'.join(content)
    return input_key


def get_server_address (config):
    server_address = config.get('url').replace('https://', '').replace('http://', '')
    if server_address.endswith('/'):
        server_address = server_address[:-1]    
    return server_address

def maybe_json_or_raise(response):
    """
    Helper function for processing request responses

    Returns any json found in the response. Otherwise, it will extract the
    response as text, or, failing that, as bytes.

    :return: the response from the request
    :rtype: dict or str or bytes
    :raises: :class:`requests.HTTPError` if status code was 4xx or 5xx
    """
    if response.ok:
        try:
            logger.info('Processing request responses.')
            return response.json(strict=False)
        except Exception:
            logger.warn(response.text or response.content)
            return response.text or response.content
    else:
        msg = ''
        try:
            msg = response.json()
            logger.warn(msg)
        except Exception:
            pass
        if not msg:
            msg = response.text
            logger.warn(msg)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            # add any response content to the error message
            error_msg = getErrorMessage(msg)
            if not error_msg:
                error_msg = '{} :: {}'.format(str(e), msg)
            logger.error(error_msg)
            raise requests.exceptions.HTTPError(error_msg, response=response)


def getErrorMessage(msg):
    if type(msg) == dict:
        error_message = msg.get('hydra:description',False)
        if error_message:
            return error_message
        error_message = msg.get('message', False)
        if error_message:
            return error_message
    return False