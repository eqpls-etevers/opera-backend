# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
from typing import Annotated
from fastapi import Request, Depends
from fastapi.security import APIKeyHeader
from fastapi.responses import RedirectResponse

from common import ORG_HEADER, AUTH_HEADER, AsyncRest

from .controls import Control

#===============================================================================
# SingleTone
#===============================================================================
ctrl = Control(__file__)
api = ctrl.api

AA_AUTH_HEADER = Annotated[str, Depends(APIKeyHeader(name='AA-Auth'))]
AA_HOST_HEADER = Annotated[str, Depends(APIKeyHeader(name='AA-Host'))]


#===============================================================================
# API Interfaces
#===============================================================================
@api.get(f'{ctrl.uri}/aa/{{url:path}}')
async def get_api(
    request:Request,
    url:str,
    org: ORG_HEADER,
    token: AUTH_HEADER,
    aaAuth: AA_AUTH_HEADER,
    aaHost: AA_HOST_HEADER
):
    if request.scope['query_string']:
        queryString = request.scope['query_string'].decode('latin-1')
        url = f'{url}?{queryString}'
    async with AsyncRest(f'https://{aaHost}/') as req:
        return await req.get(url, headers={
            'Authorization': f'Bearer {aaAuth}',
            'Accept': 'application/json; charset=utf-8'
        })


@api.post(f'{ctrl.uri}/aa/{{url:path}}')
async def post_api(
    request:Request,
    url:str,
    org: ORG_HEADER,
    token: AUTH_HEADER,
    aaAuth: AA_AUTH_HEADER,
    aaHost: AA_HOST_HEADER
):
    if request.scope['query_string']:
        queryString = request.scope['query_string'].decode('latin-1')
        url = f'{url}?{queryString}'
    async with AsyncRest(f'https://{aaHost}/') as req:
        return await req.post(url, headers={
            'Authorization': f'Bearer {aaAuth}',
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json; charset=utf-8'
        }, json=await request.json())


@api.put(f'{ctrl.uri}/aa/{{url:path}}')
async def put_api(
    request:Request,
    url:str,
    org: ORG_HEADER,
    token: AUTH_HEADER,
    aaAuth: AA_AUTH_HEADER,
    aaHost: AA_HOST_HEADER
):
    if request.scope['query_string']:
        queryString = request.scope['query_string'].decode('latin-1')
        url = f'{url}?{queryString}'
    async with AsyncRest(f'https://{aaHost}/') as req:
        return await req.put(url, headers={
            'Authorization': f'Bearer {aaAuth}',
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json; charset=utf-8'
        }, json=await request.json())


@api.patch(f'{ctrl.uri}/aa/{{url:path}}')
async def patch_api(
    request:Request,
    url:str,
    org: ORG_HEADER,
    token: AUTH_HEADER,
    aaAuth: AA_AUTH_HEADER,
    aaHost: AA_HOST_HEADER
):
    if request.scope['query_string']:
        queryString = request.scope['query_string'].decode('latin-1')
        url = f'{url}?{queryString}'
    async with AsyncRest(f'https://{aaHost}/') as req:
        return await req.patch(url, headers={
            'Authorization': f'Bearer {aaAuth}',
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json; charset=utf-8'
        }, json=await request.json())


@api.delete(f'{ctrl.uri}/aa/{{url:path}}')
async def delete_api(
    request:Request,
    url:str,
    org: ORG_HEADER,
    token: AUTH_HEADER,
    aaAuth: AA_AUTH_HEADER,
    aaHost: AA_HOST_HEADER
):
    if request.scope['query_string']:
        queryString = request.scope['query_string'].decode('latin-1')
        url = f'{url}?{queryString}'
    async with AsyncRest(f'https://{aaHost}/') as req:
        return await req.delete(url, headers={
            'Authorization': f'Bearer {aaAuth}',
            'Accept': 'application/json; charset=utf-8'
        })


@api.get(ctrl.operaLoginUri)
async def login() -> RedirectResponse:
    return RedirectResponse(url=ctrl.login())


@api.get(ctrl.operaRedirectUri)
async def callback(code:str, state:str, userstore:str) -> RedirectResponse:
    response = RedirectResponse(url=ctrl.operaHomeUrl)
    response.set_cookie(key='ARIA_ENDPOINT_ID', value=await ctrl.authorize(code, state, userstore), secure=True, samesite='none')
    return response
