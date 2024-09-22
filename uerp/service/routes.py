# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
from .controls import Control

from schema.aria import Endpoint

#===============================================================================
# SingleTone
#===============================================================================
ctrl = Control(__file__)
api = ctrl.api

#===============================================================================
# API Interfaces
#===============================================================================

@api.post('/internal/aria/endpoint', tags=['Internal Only'], name='Register Aria Endpoint Token')
async def register_aria_endpoint(endpoint:Endpoint) -> Endpoint:
    LOG.DEBUG(endpoint)
    return await endpoint.createModel()
