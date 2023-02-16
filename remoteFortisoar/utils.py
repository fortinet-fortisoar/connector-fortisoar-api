import requests
import json
from cshmac.requests import HmacAuth
from connectors.core.connector import get_logger, ConnectorError
from .constants import LOGGER_NAME

logger = get_logger(LOGGER_NAME)


def login(config):
    auth_type = config.get('auth_type')
    if auth_type == 'Basic':
        return _login_using_basic_auth(config)
    else:
        return _login_using_hmac_auth(config)
    
def invoke_rest_endpoint(config, endpoint, method='GET', headers=None, body=None, params=None):
    server_address = _get_server_address(config)
    url = 'https://{server_address}{endpoint}'.format(server_address=server_address, endpoint=endpoint)
    
    auth_type = config.get('auth_type')
    verify_ssl = config.get('verify_ssl', True)
    auth = None

    if len(headers) == 0:
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

    if (auth_type == 'Basic'):
        token = _login_using_basic_auth(config, headers)
        headers["Authorization"] = "Bearer " + token.get('token')
        return _api_call(url, method, params, body, headers, verify_ssl, auth)
    elif (auth_type == 'HMAC'):
        if body:
            logger.info("_generate_hmac: body is present")
            auth = _generate_hmac(config, url, method, _convert_payload(body))
            return _api_call(url, method, params, body, headers, verify_ssl, auth)
        elif params:
            # query params are specified
            logger.info("_generate_hmac: params is present")
            auth = _generate_hmac(config, url, method, _convert_payload(params))
            return _api_call(url=url, method=method, body=params, headers=headers, verify=verify_ssl, auth=auth)
        else:
            logger.exception('Invalid payload for auth type: {0}'.format(auth_type))
            raise ConnectorError('Invalid payload for auth type: {0}'.format(auth_type))
    else:
        logger.exception('Invalid authentication type: {0}'.format(auth_type))
        raise ConnectorError('Invalid authentication type: {0}'.format(auth_type))

def _convert_payload(payload):
    if payload and type(payload) == str:
        try:
            logger.debug('Converting payload into json: %s', payload)
            body = json.loads(payload, strict=False)
        except:
            logger.warn('Json conversion failed.')

    if payload and type(payload) != str:
        payload = json.dumps(payload)
    return payload
   
def _login_using_basic_auth(config, headers=None):
    server_address = _get_server_address(config)
    username = config.get('username')
    password = config.get('password')
    verify_ssl = config.get('verify_ssl', True)

    if headers is None:
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
    return _api_call(url=auth_url, method='POST', body=auth_payload, headers=headers, verify=verify_ssl)

def _login_using_hmac_auth(config, payload=None):
    server_address = _get_server_address(config)
    verify_ssl = config.get('verify_ssl', True)
    method = "GET"
    
    # Full URL to authenticate HMAC and connection to the remote FortiSOAR
    auth_url = 'https://{server_address}/api/auth/license/?param=license_details'.format(server_address=server_address)
   
    hmac_auth = _generate_hmac(config, auth_url, method, payload)
    return _api_call(url=auth_url, auth=hmac_auth, verify=verify_ssl)

def _generate_hmac(config, url, method, payload=None):
    public_key = _format_keys(config.get('public_key').strip())
    private_key = _format_keys(config.get('private_key').strip())
    
    if method == 'GET':
        payload = public_key
    return HmacAuth(url, method, public_key, private_key, payload)

def _api_call(url, method='GET', params='', body='', headers=None,
              verify=True, auth=None,
              *args, **kwargs):

    # build **args for requests call
    request_args = {
        'verify': verify,
    }

    if auth:
        request_args['auth'] = auth
    if params:
        request_args['params'] = params
    if headers:
        request_args['headers'] = headers

    # get rid of the body on GET/HEAD requests
    bodyless_methods = ['head', 'get']
    if method.lower() not in bodyless_methods:
        request_args['data'] = _convert_payload(body)

    # actual requests call
    logger.info('Starting request: Method: %s, Url: %s', method, url)
    try:
        response = requests.request(method, url, **request_args)
    except requests.exceptions.SSLError as e:
        logger.exception("ERROR :: {0}".format(str(e)))
        raise ConnectorError("ERROR :: {0}".format(str(e)))
    return _maybe_json_or_raise(response)

def _format_keys(input_key):
    content = input_key.split('-----')
    content[2] = content[2].replace(' ', '\n')
    input_key = '-----'.join(content)
    return input_key

def _get_server_address (config):
    server_address = config.get('url').replace('https://', '').replace('http://', '')
    if server_address.endswith('/'):
        server_address = server_address[:-1]    
    return server_address

def _maybe_json_or_raise(response):
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
            error_msg = _getErrorMessage(msg)
            if not error_msg:
                error_msg = '{} :: {}'.format(str(e), msg)
            logger.error(error_msg)
            raise requests.exceptions.HTTPError(error_msg, response=response)

def _getErrorMessage(msg):
    if type(msg) == dict:
        error_message = msg.get('hydra:description',False)
        if error_message:
            return error_message
        error_message = msg.get('message', False)
        if error_message:
            return error_message
    return False