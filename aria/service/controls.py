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

        self.ariaClientId = self.config['aria']['client_id']
        self.ariaClientSecret = self.config['aria']['client_secret']
        self.ariaRedirectUri = self.config['aria']['redirect_uri']

        self.ariaVidmHostname = self.config['aria']['vidm_hostname']
        self.ariaVidmAuth = base64.b64encode(f'{self.ariaClientId}:{self.ariaClientSecret}'.encode('ascii')).decode('ascii')
        self.ariaVidmHeaders = {
            'Authorization': f'Basic {self.ariaVidmAuth}'
        }

        self.ariaAAHostname = self.config['aria']['aa_hostname']

    async def startup(self): pass

    async def shutdown(self): pass

    def generateUuid4(self): return str(uuid.uuid4())

    def login(self):
        return f'https://{self.ariaVidmHostname}/SAAS/auth/oauth2/authorize?response_type=code&state={self.generateUuid4()}&client_id={self.ariaClientId}&redirect_uri={self.ariaRedirectUri}'

    async def callback(self, code:str, state:str, userstore:str):
        LOG.DEBUG(code)
        LOG.DEBUG(state)
        LOG.DEBUG(userstore)

        async with AsyncRest(f'https://{self.ariaVidmHostname}') as req:
            return await req.post(f'/SAAS/auth/oauthtoken?grant_type=authorization_code&code={code}&redirect_uri={self.ariaRedirectUri}', headers=self.ariaVidmHeaders)
