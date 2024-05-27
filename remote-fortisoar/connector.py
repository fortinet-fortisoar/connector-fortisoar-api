"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from django.utils.module_loading import import_string
from .builtins import *
from .constants import LOGGER_NAME
from .health_check import health_check

logger = get_logger(LOGGER_NAME)

class Remotefortisoar(Connector):

    def execute(self, config, operation, params, *args, **kwargs):
        return supported_operations.get(operation)(config, params)

    def check_health(self, config=None, *args, **kwargs):
        return health_check(config, *args, **kwargs)