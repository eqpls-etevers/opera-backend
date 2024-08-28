# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
from fastapi.responses import RedirectResponse

from .controls import Control

#===============================================================================
# SingleTone
#===============================================================================
ctrl = Control(__file__)
api = ctrl.api


#===============================================================================
# API Interfaces
#===============================================================================
@api.get(ctrl.loginUri)
async def login() -> RedirectResponse:
    return RedirectResponse(url=ctrl.login())


@api.get(ctrl.redirectUri)
async def callback(code:str, state:str, userstore:str) -> RedirectResponse:
    response = RedirectResponse(url=ctrl.homeUrl)
    response.set_cookie(key='ARIA_ENDPOINT_ID', value=await ctrl.authorize(code, state, userstore))
    return response
