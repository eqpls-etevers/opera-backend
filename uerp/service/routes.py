# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
from fastapi.middleware.cors import CORSMiddleware

from .controls import Control

from schema.aria import Endpoint

#===============================================================================
# SingleTone
#===============================================================================
ctrl = Control(__file__)
api = ctrl.api

origins = ['*']
api.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


#===============================================================================
# API Interfaces
#===============================================================================
@api.post('/internal/aria/endpoint', tags=['Internal Only'], name='Register Aria Endpoint Token')
async def register_aria_endpoint(endpoint:Endpoint) -> Endpoint:
    return await endpoint.createModel()
