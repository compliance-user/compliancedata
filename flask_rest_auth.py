#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import logging

from datetime import datetime
from bson import ObjectId

from flask import Flask, request
from flask_restful import Api, Resource
from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/user_interface')
db = client['user_interface']

application = Flask(__name__)

api = Api(application)

logging.basicConfig(level='INFO')


class Users(Resource):

    def get(self, user_id=None, action_name=None):
        if action_name == 'get_user' and user_id:
            user_detail = db.user.find_one({'_id': ObjectId(user_id)})
            if user_detail:
                user_detail.pop('_id')
                user_detail['created_at'] = str(user_detail['created_at'
                        ])
                user_detail['updated_at'] = str(user_detail['updated_at'
                        ])
                return {
                    'status': 'success',
                    'data': user_detail,
                    'code': 200,
                    'message': 'User info retrieved successfully',
                    }
            else:
                return {
                    'Status': 'Error',
                    'data': {},
                    'code': 400,
                    'message': 'Unable to get user',
                    }
        else:
            return {
                'status': 'Error',
                'data': {},
                'code': 404,
                'message': 'URL not found',
                }

    def post(self, action_name=None):
        user_info = {}
        if action_name == 'create_user':
            user_existence = \
                db.user.find_one({'username': request.headers['User']})
            if not user_existence:
                if request.headers['User'] \
                    and request.headers['Password']:
                    db.user.insert({
                        'username': request.headers['User'],
                        'password': request.headers['Password'],
                        'created_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow(),
                        'is_active': True,
                        })
                    return {'status': 'success', 'code': 201,
                            'message': 'User created'}
            else:
                return {'status': 'error', 'code': 409,
                        'message': 'Username already exists'}
        else:
            return {
                'status': 'error',
                'code': 404,
                'message': 'URL not found',
                'data': {},
                }

    def put(self, user_id, action_name=None):
        if user_id and action_name == 'update_user':
            check_user_exists = \
                db.user.find_one({'_id': ObjectId(user_id)})
            if check_user_exists:
                db.user.update({'_id': ObjectId(user_id)},
                               {'$set': {'username': request.headers['User'
                               ], 'password': request.headers['Password'
                               ], 'updated_at': datetime.utcnow()}})
                return {'status': 'success', 'code': 204,
                        'message': 'User updated successfully'}
            else:
                return {'status': 'error', 'code': 400,
                        'message': 'Unable to update user'}
        else:
            return {'status': 'error', 'code': 404,
                    'message': 'URL not found'}

    def delete(self, user_id, action_name=None):
        if user_id and action_name == 'delete_user':
            db.user.remove({'_id': ObjectId(user_id)})
            return {'status': 202,
                    'message': 'User deleted successfully'}


api.add_resource(Users, '/v1/api/<user_id>/<action_name>',
                 '/v1/api/auth/tokens/<action_name>')

if __name__ == '__main__':
    application.run(port=8001, debug=True)

# Request examples
# get    > requetst.get('http://localhost:8001/v1/api/6208934eb9668289417fc20f/get_user')
# post   > requests.post('http://localhost:8001/v1/api/auth/tokens/create_user', headers={'User': 'david', 'Password': '123'})
# put    > requests.put('http://localhost:8001/v1/api/6208934eb9668289417fc20f/update_user', headers={'User': 'DavidBeckham', 'password': 'Beck@123'})
# delete > requests.delete('http://localhost:8001/v1/api/6208934eb9668289417fc20f/delete_user')
