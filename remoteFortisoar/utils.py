import requests
import json
from cshmac.requests import HmacAuth
from connectors.core.connector import get_logger, ConnectorError
from .constants import LOGGER_NAME

logger = get_logger(LOGGER_NAME)


def invoke_rest_endpoint(config, endpoint, method='GET', data=None, headers=None):
    server_address = get_server_address(config)

    url = 'https://{server_address}{endpoint}'.format(server_address=server_address, endpoint=endpoint)
    verify_ssl = config.get('verify_ssl', True)
    auth_type = config.get('auth_type')
    auth_token = None
   
    if (auth_type == 'Basic'):
        if headers is None:
            headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
        token = login(config)
        headers["Authorization"] = "Bearer " + token
    elif (auth_type == 'HMAC'):
        logger.info("Login using HMAC Auth")
        auth_token = get_hmac_auth_token(config, url, method, data)
    else:
        logger.exception('Invalid authentication type: {0}'.format(auth_type))
        raise ConnectorError('Invalid authentication type: {0}'.format(auth_type))
        
    try:
        response = requests.request(method, url, auth=auth_token, verify=verify_ssl, json=data, headers=headers)
    except Exception as e:
        logger.exception('Error invoking endpoint: {0}'.format(url))
        raise ConnectorError('Error: {0}'.format(str(e)))
    if response.ok:
        return response.json()
    else:
        logger.error(response.content)
        raise ConnectorError(response.content)


def login(config):
    auth_type = config.get('auth_type')
    if auth_type == 'Basic':
        return login_using_basic_auth(config)
    else:
        return login_using_hmac_auth(config)
  
  
def login_using_hmac_auth(config, data=None):
    logger.info("Login using HMAC Auth")
    server_address = get_server_address(config)
    
    # dummy url to authenticate HMAC creds
    auth_url = 'https://{server_address}/api/3/alerts'.format(server_address=server_address)
    
    try:
        auth_token = get_hmac_auth_token(config, auth_url, 'get', data)
    except Exception as e:
        logger.exception('Error invoking endpoint: {0}'.format(auth_url))
        raise ConnectorError('Error: {0}'.format(str(e)))
    if auth_token:
        return auth_token
    else:
        logger.error("HMAC authentication failed")
        raise ConnectorError("HMAC authentication failed")

    return None


def login_using_basic_auth(config):
    logger.info("Login using Basic Auth")
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
        response = requests.request('post', auth_url, verify=verify_ssl, json=auth_payload, headers=headers)
    except Exception as e:
        logger.exception('Error invoking endpoint: {0}'.format(auth_url))
        raise ConnectorError('Error: {0}'.format(str(e)))
    if response.ok:
        data = response.json()
        return data.get('token')
    else:
        logger.error(response.content)
        raise ConnectorError(response.content)


def get_server_address (config):
    server_address = config.get('url').replace('https://', '').replace('http://', '')
    if server_address.endswith('/'):
        server_address = server_address[:-1]
    
    return server_address


def get_hmac_auth_token(config, url, method, data):
    public_key = config.get('public_key')
    public_key = format_keys(public_key)
    private_key = config.get('private_key')
    private_key = format_keys(private_key)
    
    if data:
        auth_token = HmacAuth(url, method, public_key, private_key, data)
    else:
        auth_token = HmacAuth(url, method, public_key, private_key, public_key.encode('utf-8'))
    return auth_token


def format_keys(input_key):
    content = input_key.split('-----')
    content[2] = content[2].replace(' ', '\n')
    input_key = '-----'.join(content)
    return input_key