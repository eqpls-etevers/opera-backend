# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
import re
import uuid
import base64

from common import getRandomString, MeshControl, AsyncRest
from schema.aria import Endpoint


#===============================================================================
# Implement
#===============================================================================
class Control(MeshControl):

    def __init__(self, path):
        MeshControl.__init__(self, path, sessionChecker='uerp')

        self.domain = self.config['default']['domain']
        self.endpoint = self.config['default']['endpoint']
        
        uerpHostname = self.config['uerp']['hostname']
        uerpHostport = self.config['uerp']['hostport']
        self.uerpEndpoint = f'http://{uerpHostname}:{uerpHostport}'
        
        self.operaClientId = self.endpoint.replace('.', '-')
        self.operaHomeUrl = f'https://{self.endpoint}'
        self.operaLoginUri = f'{self.uri}/auth/login'
        self.operaRedirectUri = f'{self.uri}/auth/callback'
        self.operaRedirectUrl = f'https://{self.endpoint}{self.operaRedirectUri}'

        self.vidmHostname = self.config['aria']['vidm_hostname']
        self.vidmClientId = self.config['aria']['vidm_client_id']
        self.vidmClientSecret = self.config['aria']['vidm_client_secret']
        self.vidmBaseUrl = f'https://{self.vidmHostname}'
        self.vidmHeaders = {
            'Authorization': 'Basic ' + base64.b64encode(f'{self.vidmClientId}:{self.vidmClientSecret}'.encode('ascii')).decode('ascii')
        }
        
        self.aaClientPrefix = self.config['aria']['aa_client_prefix']
        self.aaMap = {}
        
        # self.aaHostname = self.config['aria']['aa_hostname']
        # self.aaClientId = self.config['aria']['aa_client_id']
        # self.aaRedirectUri = self.config['aria']['aa_redirect_uri']
        # self.aaState = base64.b64encode(f'https://{self.aaHostname}/provisioning/access-token'.encode('ascii')).decode('ascii')

    async def startup(self):
        await self.registerModel(Endpoint, 'uerp')
        await self.initAriaBackends()

    async def shutdown(self): pass

    def generateUuid4(self): return str(uuid.uuid4())
    
    async def initAriaBackends(self):
        async with AsyncRest(self.vidmBaseUrl) as req:
            vidmAccessToken = (await req.post('/SAAS/auth/oauthtoken?grant_type=client_credentials', headers=self.vidmHeaders))['access_token']
            vidmBearerToken = f'Bearer {vidmAccessToken}'
            headers = {
                'Authorization': vidmBearerToken
            }
            
            vidmOperaClient = None
            vidmAaClientIds = []
            for client in (await req.get('/SAAS/jersey/manager/api/oauth2clients', headers=headers))['items']:
                clientId = client['clientId']
                if self.endpoint in clientId: vidmOperaClient = client
                elif self.aaClientPrefix in clientId and client['scope'] == 'user openid email profile': vidmAaClientIds.append(client['clientId'])
            
            if not vidmOperaClient:
                secret = getRandomString(16)
                async with AsyncRest(self.vidmBaseUrl) as req:
                    vidmOperaClient = await req.post('/SAAS/jersey/manager/api/oauth2clients', headers={
                        'Authorization': vidmBearerToken,
                        'Content-Type': 'application/vnd.vmware.horizon.manager.oauth2client+json',
                        'Accept': 'application/vnd.vmware.horizon.manager.oauth2client+json'
                    }, json={
                        'clientId': self.endpoint,
                        'rememberAs': self.endpoint,
                        'secret': secret,
                        'redirectUri': self.operaRedirectUrl,
                        'scope': 'email profile user openid',
                        'authGrantTypes': 'authorization_code refresh_token',
                        'tokenType': 'Bearer',
                        'tokenLength': 32,
                        'accessTokenTTL': 180,
                        'refreshTokenTTL': 129600,
                        'refreshTokenIdleTTL': 5760,
                        'displayUserGrant': False,
                        'internalSystemClient': False,
                        'activationToken': None,
                        'strData': None,
                        'inheritanceAllowed': False,
                        'returnFailureResponse': False
                    })
            else:
                async with AsyncRest(self.vidmBaseUrl) as req:
                    vidmOperaClient = await req.get(f'/SAAS/jersey/manager/api/oauth2clients/{vidmOperaClient["clientId"]}', headers=headers)
            self.vidmOperaSecret = vidmOperaClient['secret']
            
            async with AsyncRest(self.vidmBaseUrl) as req:
                for clientId in vidmAaClientIds:
                    client = await req.get(f'/SAAS/jersey/manager/api/oauth2clients/{clientId}', headers=headers)
                    redirectUri = [redirectUri.strip() for redirectUri in client['redirectUri'].split(',')][0]
                    hostname = re.match('^https:\/\/(?P<hostName>[^\/]+)\/', redirectUri)['hostName']
                    self.aaMap[hostname] = {
                        'clientId': clientId,
                        'redirectUri': redirectUri
                    }
    
    def login(self):
        return f'https://{self.vidmHostname}/SAAS/auth/oauth2/authorize?domain={self.domain}&response_type=code&state={self.generateUuid4()}&client_id={self.endpoint}&redirect_uri={self.operaRedirectUrl}'

    async def authorize(self, code:str, state:str, userstore:str):
        
        LOG.DEBUG(code)
        LOG.DEBUG(state)
        
        async with AsyncRest(f'https://{self.vidmHostname}') as req:
            vidmTokens = await req.post(f'/SAAS/auth/oauthtoken?grant_type=authorization_code&code={code}&state={state}&redirect_uri={self.operaRedirectUrl}', headers=self.vidmHeaders)
        vidmAccessToken = vidmTokens['access_token']
        
        LOG.DEBUG(vidmAccessToken)
        
        aa = []
        async with AsyncRest(f'https://{self.vidmHostname}') as req:
            for hostname, client in self.aaMap.items():
                clientId = client['clientId']
                redirectUri = client['redirectUri']
                state = base64.b64encode(f'https://{hostname}/identity/api/access-token'.encode('ascii')).decode('ascii')
                
                LOG.DEBUG(clientId)
                LOG.DEBUG(redirectUri)
                LOG.DEBUG(state)
                
                aaTokens = await req.get(f'/SAAS/auth/oauth2/authorize?response_type=code&client_id={clientId}&redirect_uri={redirectUri}&state={state}', headers={
                    'Authorization': f'Bearer {vidmAccessToken}'
                })
                
                LOG.DEBUG(aaTokens)
                
                aa.append({
                    'hostname': hostname,
                    'accessToken': aaTokens['access_token'],
                    'refreshToken': aaTokens['refresh_token']
                })
        async with AsyncRest(self.uerpEndpoint) as req:
            endpoint = await req.post('/internal/aria/endpoint', json={
                'vidm': {
                    'hostname': self.vidmHostname,
                    'accessToken': vidmAccessToken,
                    'refreshToken': vidmTokens['refresh_token']
                },
                'aa': aa
            })
            
        return endpoint['id']
