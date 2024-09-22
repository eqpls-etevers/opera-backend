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
from common import CRUD, LAYER, AAA, SECONDS, SchemaConfig, Option, BaseSchema


#===============================================================================
# Implement
#===============================================================================
@SchemaConfig(
version=3,
layer=LAYER.C,
aaa=AAA.A,
cache=Option(expire=3 * SECONDS.HOUR))
class Endpoint(BaseModel, BaseSchema):

    class VIDM(BaseModel):
        hostname:str
        accessToken:str
        refreshToken:str

    class Region(BaseModel):
        name:str
        hostname:str
        accessToken:str
        status:bool

    vidm:VIDM
    regions:List[Region] = []
