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

from common import getRandomString, MeshControl, AsyncRest, EpException
from schema.aria import Endpoint

from driver.keyclock import KeyCloak


#===============================================================================
# Implement
#===============================================================================
class Control(MeshControl):

    def __init__(self, path):
        MeshControl.__init__(self, path, sessionChecker='uerp')

        self.keycloak = KeyCloak(self.config)

        self.tenant = self.config['default']['tenant']
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
        self.vidmAdminHeaders = {
            'Authorization': 'Basic ' + base64.b64encode(f'{self.vidmClientId}:{self.vidmClientSecret}'.encode('ascii')).decode('ascii')
        }

        self.aaClientPrefix = self.config['aria']['aa_client_prefix']
        self.aaMap = {}

    async def startup(self):
        await self.registerModel(Endpoint, 'uerp')
        await self.keycloak.connect()
        await self.initAriaBackends()

    async def shutdown(self): pass

    def generateUuid4(self): return str(uuid.uuid4())

    async def initAriaBackends(self):
        async with AsyncRest(self.vidmBaseUrl) as req:
            vidmAccessToken = (await req.post('/SAAS/auth/oauthtoken?grant_type=client_credentials', headers=self.vidmAdminHeaders))['access_token']
            vidmBearerToken = f'Bearer {vidmAccessToken}'
            headers = {'Authorization': vidmBearerToken}

            vidmOperaClient = None
            vidmAaClientIds = []
            for client in (await req.get('/SAAS/jersey/manager/api/oauth2clients', headers=headers))['items']:
                clientId = client['clientId']
                if self.endpoint == clientId: vidmOperaClient = client
                elif self.aaClientPrefix in clientId and client['scope'] == 'user openid email profile': vidmAaClientIds.append(client['clientId'])

            if not vidmOperaClient:
                realmId = self.tenant

                async with AsyncRest(self.keycloak._kcBaseUrl) as req:
                    kcIdpMetadata = await req.get(f'/realms/{realmId}/protocol/saml/descriptor')
                LOG.DEBUG(kcIdpMetadata)
                if not kcIdpMetadata: raise Exception('hahahah')

                await self.keycloak.post(f'/admin/realms/{realmId}/client-scopes', {
                    'name': 'vidm-scope',
                    'description': 'vidm-scope',
                    'type': 'default',
                    'protocol': 'saml',
                    'attributes': {
                        'consent.screen.text': '',
                        'display.on.consent.screen': True,
                        'include.in.token.scope': True,
                        'gui.order': ''
                    }
                })
                for scope in await self.keycloak.get(f'/admin/realms/{realmId}/client-scopes'):
                    if scope['name'] == 'vidm-scope': scopeId = scope['id']; break
                else: raise EpException(404, 'Could not find client scope')
                await self.keycloak.post(f'/admin/realms/{realmId}/client-scopes/{scopeId}/protocol-mappers/models', {
                    'name': 'userName',
                    'protocol': 'saml',
                    'protocolMapper': 'saml-user-property-mapper',
                    'config': {
                        'friendly.name': 'userName',
                        'attribute.name': 'userName',
                        'attribute.nameformat': 'Basic',
                        'user.attribute': 'username'
                    }
                })
                await self.keycloak.post(f'/admin/realms/{realmId}/client-scopes/{scopeId}/protocol-mappers/models', {
                    'name': 'email',
                    'protocol': 'saml',
                    'protocolMapper': 'saml-user-property-mapper',
                    'config': {
                        'friendly.name': 'email',
                        'attribute.name': 'email',
                        'attribute.nameformat': 'Basic',
                        'user.attribute': 'email'
                    }
                })
                await self.keycloak.post(f'/admin/realms/{realmId}/client-scopes/{scopeId}/protocol-mappers/models', {
                    'name': 'surname',
                    'protocol': 'saml',
                    'protocolMapper': 'saml-user-property-mapper',
                    'config': {
                        'friendly.name': 'surname',
                        'attribute.name': 'lastName',
                        'attribute.nameformat': 'Basic',
                        'user.attribute': 'lastName'
                    }
                })
                await self.keycloak.post(f'/admin/realms/{realmId}/client-scopes/{scopeId}/protocol-mappers/models', {
                    'name': 'givenName',
                    'protocol': 'saml',
                    'protocolMapper': 'saml-user-property-mapper',
                    'config': {
                        'friendly.name': 'givenName',
                        'attribute.name': 'firstName',
                        'attribute.nameformat': 'Basic',
                        'user.attribute': 'firstName'
                    }
                })

                await self.keycloak.post(f'/admin/realms/{realmId}/clients', {
                    'clientId': f'https://{self.vidmHostname}/SAAS/API/1.0/GET/metadata/sp.xml',
                    'name': 'vidm',
                    'description': 'vidm',
                    'protocol': 'saml',
                    'publicClient': True,
                    'rootUrl': f'https://{self.vidmHostname}',
                    'baseUrl': f'https://{self.vidmHostname}',
                    'adminUrl': f'https://{self.vidmHostname}/SAAS/auth/saml/response',
                    'redirectUris': ['*'],
                    'authorizationServicesEnabled': False,
                    'serviceAccountsEnabled': False,
                    'implicitFlowEnabled': False,
                    'directAccessGrantsEnabled': True,
                    'standardFlowEnabled': True,
                    'frontchannelLogout': True,
                    'alwaysDisplayInConsole': True,
                    'attributes': {
                        'saml_idp_initiated_sso_url_name': '',
                        'saml_idp_initiated_sso_relay_state': '',
                        'post.logout.redirect.uris': '+'
                    }
                })
                for client in await self.keycloak.get(f'/admin/realms/{realmId}/clients'):
                    if client['name'] == 'vidm':
                        clientId = client['id'];
                        client['frontchannelLogout'] = False
                        client['attributes']['saml.client.signature'] = 'false'
                        client['attributes']['saml.server.signature.keyinfo.xmlSigKeyInfoKeyNameTransformer'] = 'KEY_ID'
                        client['attributes']['saml.encrypt'] = 'false'
                        client['attributes']['logoUri'] = ''
                        client['attributes']['policyUri'] = ''
                        client['attributes']['tosUri'] = ''
                        client['attributes']['saml_assertion_consumer_url_post'] = f'https://{self.vidmHostname}/SAAS/auth/saml/response'
                        client['attributes']['saml_assertion_consumer_url_redirect'] = f'https://{self.vidmHostname}/SAAS/auth/saml/response'
                        client['attributes']['saml_single_logout_service_url_post'] = ''
                        client['attributes']['saml_single_logout_service_url_redirect'] = ''
                        client['attributes']['saml_single_logout_service_url_soap'] = ''
                        client['attributes']['saml_single_logout_service_url_artifact'] = ''
                        client['attributes']['saml_artifact_binding_url'] = ''
                        client['attributes']['saml_artifact_resolution_service_url'] = ''
                        client['attributes']['saml.assertion.lifespan'] = ''
                        client['authenticationFlowBindingOverrides']['browser'] = ''
                        await self.keycloak.put(f'/admin/realms/opera/clients/{clientId}', client)
                        await self.keycloak.put(f'/admin/realms/opera/clients/{clientId}/default-client-scopes/{scopeId}', {})
                        break
                else: raise EpException(404, 'Could not find client')

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

                    orgNetworks = (await req.get('/SAAS/jersey/manager/api/orgnetworks', headers={
                        'Authorization': vidmBearerToken,
                        'Accept': 'application/vnd.vmware.horizon.manager.orgnetwork.list+json'
                    }))['items']
                    for orgNetwork in orgNetworks:
                        if orgNetwork['name'] == 'ALL RANGES':
                            allRange = orgNetwork
                            allRange.pop('_links')
                            break
                    else: raise Exception('could not find ALL RANGES org network in vidm')

                    vidmJitDir = await req.post('/SAAS/jersey/manager/api/connectormanagement/directoryconfigs', headers={
                        'Authorization': vidmBearerToken,
                        'Content-Type': 'application/vnd.vmware.horizon.manager.connector.management.directory.jit+json',
                        'Accept': 'application/vnd.vmware.horizon.manager.connector.management.directory.jit+json'
                    }, json={
                        'name': self.tenant,
                        'domains': ['portal.lab'] # ONLY TEST
                    })

                    await req.post('/SAAS/jersey/manager/api/identityProviders', headers={
                        'Authorization': vidmBearerToken,
                        'Content-Type': 'application/vnd.vmware.horizon.manager.external.identityprovider+json',
                        'Accept': 'application/vnd.vmware.horizon.manager.external.identityprovider+json'
                    }, json={
                        'authMethods': [{
                            'authMethodId': 0,
                            'authScore': 1,
                            'defaultMethod': False,
                            'authMethodOrder': 0,
                            'authMethodName': self.tenant,
                            'samlAuthnContext': 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'
                        }],
                        'identityProviderType': 'MANUAL',
                        'nameIdFormatType': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                        'friendlyName': self.tenant,
                        'metaData': kcIdpMetadata,
                        'preferredBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                        'jitEnabled': True,
                        'directoryConfigurations': [{
                            'type': 'JIT_DIRECTORY',
                            'name': self.tenant,
                            'directoryId': vidmJitDir['directoryConfigurationId'],
                            'userstoreId': vidmJitDir['userStoreId'],
                            'countDomains': 1,
                            'deleteInProgress': False,
                            'syncConfigurationEnabled': False
                        }],
                        'customAttributeMappings': None,
                        'nameIdFormatAttributeMappings': {
                            'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified': 'userName',
                            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress': 'emails',
                            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent': 'id',
                            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient': 'userName'
                        },
                        'orgNetworks': [allRange],
                        'description': '',
                        'nIDPStatus': 1,
                        'idpURL': None,
                        'name': self.tenant
                    })
            else:
                async with AsyncRest(self.vidmBaseUrl) as req:
                    vidmOperaClient = await req.get(f'/SAAS/jersey/manager/api/oauth2clients/{vidmOperaClient["clientId"]}', headers=headers)
            self.vidmOperaSecret = vidmOperaClient['secret']
            self.vidmOperaHeaders = {
                'Authorization': 'Basic ' + base64.b64encode(f'{self.endpoint}:{self.vidmOperaSecret}'.encode('ascii')).decode('ascii')
            }

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
        # return f'https://{self.vidmHostname}/SAAS/auth/oauth2/authorize?domain={self.domain}&response_type=code&state={self.generateUuid4()}&client_id={self.endpoint}&redirect_uri={self.operaRedirectUrl}'
        return f'https://{self.vidmHostname}/SAAS/auth/oauth2/authorize?domain=portal.lab&response_type=code&state={self.generateUuid4()}&client_id={self.endpoint}&redirect_uri={self.operaRedirectUrl}'

    async def authorize(self, code:str, state:str, userstore:str):
        async with AsyncRest(f'https://{self.vidmHostname}') as req:
            vidmTokens = await req.post(f'/SAAS/auth/oauthtoken?grant_type=authorization_code&code={code}&redirect_uri={self.operaRedirectUrl}', headers=self.vidmOperaHeaders)
        vidmAccessToken = vidmTokens['access_token']
        regions = []
        async with AsyncRest(f'https://{self.vidmHostname}') as req:
            for hostname, client in self.aaMap.items():
                clientId = client['clientId']
                redirectUri = client['redirectUri']
                state = base64.b64encode(f'https://{hostname}/identity/api/access-token'.encode('ascii')).decode('ascii')
                try:
                    aaAccessToken = (await req.get(f'/SAAS/auth/oauth2/authorize?response_type=code&client_id={clientId}&redirect_uri={redirectUri}&state={state}', headers={
                        'Authorization': f'Bearer {vidmAccessToken}'
                    }))['access_token']
                    async with AsyncRest(f'https://{hostname}') as req:
                        res = await req.get('/userprofile/api/branding/byservice/cloud_assembly', {
                            'Authorization': f'Bearer {aaAccessToken}',
                            'Accept': 'application/json'
                        })
                        if res['content'] and 'serviceName' in res['content'][0]: branding = res['content'][0]['serviceName']
                        else: branding = hostname
                except: branding = None
                regions.append({
                    'name': branding if branding else hostname,
                    'hostname': hostname,
                    'accessToken': aaAccessToken if branding else '',
                    'status': True if branding else False
                })
        async with AsyncRest(self.uerpEndpoint) as req:
            endpoint = await req.post('/internal/aria/endpoint', json={
                'vidm': {
                    'hostname': self.vidmHostname,
                    'accessToken': vidmAccessToken,
                    'refreshToken': vidmTokens['refresh_token']
                },
                'regions': regions
            })
        return endpoint['id']

