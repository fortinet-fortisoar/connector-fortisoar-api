"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
import json
from .utils import invoke_rest_endpoint, upload_file_remote
from .constants import LOGGER_NAME
import os
from django.conf import settings
from connectors.cyops_utilities.builtins import download_file_from_cyops

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


def upload_file(config, params, *args, **kwargs):
    file_iri = params.get('file_iri')
    create_attachment = params.get('create_attachment')
    if not file_iri:
        logger.warning('Got file_iri: {file_iri}'.format(endpoint=file_iri))
        raise ConnectorError('Missing required input')
    dw_file_md = download_file_from_cyops(file_iri)
    tmp_file_path = dw_file_md.get('cyops_file_path')
    file_name = dw_file_md.get('filename')
    logger.info('file_name = {0}'.format(file_name))
    file_path = os.path.join(settings.TMP_FILE_ROOT, tmp_file_path)
    api_response = upload_file_remote(config, open(file_path, 'rb'), dw_file_md, create_attachment)
    return api_response
