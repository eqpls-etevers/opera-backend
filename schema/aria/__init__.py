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
version=2,
layer=LAYER.C,
aaa=AAA.A,
cache=Option(expire=3 * SECONDS.HOUR))
class Endpoint(BaseModel, BaseSchema):
    
    class Info(BaseModel):
        hostname:str
        name:str
        accessToken:str
        refreshToken:str
        status:bool
    
    vidm:Info
    aa:List[Info] = []
