"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
import json
from .utils import invoke_rest_endpoint
from .constants import LOGGER_NAME

logger = get_logger(LOGGER_NAME)

def make_api_call(config, params, *args, **kwargs):
    endpoint = params.get('iri')
    method = params.get('method')
    headers = params.get('headers', None)
    body = params.get('body', None)
    param = params.get('params', None)
    if not endpoint or not method:
        logger.warning('Got an endpoint: {endpoint}\Body: {body}'.format(endpoint=endpoint, body=json.dumps(body)))
        raise ConnectorError('Missing required input')

    api_response = invoke_rest_endpoint(config, endpoint, method, headers, body, param)
    return api_response

