# -*- coding: utf-8 -*-
'''
Equal Plus
@author: Hye-Churn Jang
'''

#===============================================================================
# Import
#===============================================================================
from typing import List
from pydantic import BaseModel
from common import LAYER, AAA, SECONDS, SchemaConfig, Option, BaseSchema, ProfSchema


#===============================================================================
# Implement
#===============================================================================
@SchemaConfig(
version=1,
layer=LAYER.C,
aaa=AAA.A,
cache=Option(expire=SECONDS.HOUR))
class Endpoint(BaseModel, BaseSchema):
    
    class Token(BaseModel):
        hostname:str = ''
        accessToken:str = ''
        refreshToken:str = ''
    
    vidm:Token
    aa:List[Token] = []
    
