from connectors.core.connector import get_logger, ConnectorError
import json
from .utils import invoke_rest_endpoint
from .constants import LOGGER_NAME

logger = get_logger(LOGGER_NAME)

def make_api_call(config, params, *args, **kwargs):
    endpoint = params.get('iri')
    data = params.get('data', None)
    method = params.get('method')
    if not endpoint or not method:
        logger.warning('Got endpoint: {endpoint}\nData: {data}'.format(endpoint=endpoint, data=json.dumps(data)))
        raise ConnectorError('Missing required input')

    api_response = invoke_rest_endpoint(config, endpoint, method, data)
    return api_response

