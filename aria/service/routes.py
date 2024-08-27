# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
from fastapi.responses import RedirectResponse

from common import EpException, ID, AUTH_HEADER, ORG_HEADER

from .controls import Control

#===============================================================================
# SingleTone
#===============================================================================
ctrl = Control(__file__)
api = ctrl.api


#===============================================================================
# API Interfaces
#===============================================================================
@api.get(f'{ctrl.uri}/auth/login')
async def login() -> RedirectResponse:
    return RedirectResponse(url=ctrl.login())


@api.get(f'{ctrl.uri}/auth/callback')
async def callback(code:str, state:str, userstore:str) -> dict:
    return await ctrl.callback(code, state, userstore)


@api.get(f'{ctrl.uri}/auth/authorize')
async def authorize(
    org: ORG_HEADER,
    token: AUTH_HEADER,
) -> dict:
    return await ctrl.authorize(token.credentials)
