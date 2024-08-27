# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
import uuid
import base64

from common import MeshControl, AsyncRest


#===============================================================================
# Implement
#===============================================================================
class Control(MeshControl):

    def __init__(self, path):
        MeshControl.__init__(self, path, sessionChecker='uerp')

        self.domain = self.config['default']['domain']
        self.endpoint = self.config['default']['endpoint']
        self.homeUrl = f'https://{self.endpoint}'
        self.loginUri = f'{self.uri}/auth/login'
        self.redirectUri = f'{self.uri}/auth/callback'
        self.redirectUrl = f'https://{self.endpoint}{self.redirectUri}'

        self.vidmHostname = self.config['aria']['vidm_hostname']
        self.vidmClientId = self.config['aria']['vidm_client_id']
        self.vidmClientSecret = self.config['aria']['vidm_client_secret']
        self.vidmHeaders = {
            'Authorization': 'Basic ' + base64.b64encode(f'{self.vidmClientId}:{self.vidmClientSecret}'.encode('ascii')).decode('ascii')
        }

        self.aaHostname = self.config['aria']['aa_hostname']
        self.aaClientId = self.config['aria']['aa_client_id']
        self.aaRedirectUri = self.config['aria']['aa_redirect_uri']
        self.aaState = base64.b64encode(f'https://{self.aaHostname}/provisioning/access-token'.encode('ascii')).decode('ascii')

    async def startup(self): pass

    async def shutdown(self): pass

    def generateUuid4(self): return str(uuid.uuid4())

    def login(self):
        return f'https://{self.vidmHostname}/SAAS/auth/oauth2/authorize?domain={self.domain}&response_type=code&state={self.generateUuid4()}&client_id={self.vidmClientId}&redirect_uri={self.redirectUrl}'

    async def callback(self, code:str, state:str, userstore:str):
        async with AsyncRest(f'https://{self.vidmHostname}') as req:
            res = await req.post(f'/SAAS/auth/oauthtoken?grant_type=authorization_code&code={code}&redirect_uri={self.redirectUrl}', headers=self.vidmHeaders)
        async with AsyncRest(f'https://{self.vidmHostname}') as req:
            res = await req.get(f'/SAAS/auth/oauth2/authorize?response_type=code&client_id={self.aaClientId}&redirect_uri={self.aaRedirectUri}&state={self.aaState}', headers={
                'Authorization': f'Bearer {res["access_token"]}'
            })
        return res['access_token']
