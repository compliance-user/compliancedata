# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import json
import multiprocessing
import os
import re
import sys
import time
from base64 import b64encode
from datetime import datetime, timedelta

import pyodbc
import requests
import yaql
from pymongo import MongoClient

from cs_policy_interface.definitions import ConnectorEngines, cs_policy_storage
from cs_policy_interface.sql_metadata import get_query_tables

pyodbc.pooling = False

_ver = sys.version_info
is_py3 = (_ver[0] == 3)

if is_py3:
    from urllib.parse import quote_plus
else:
    from urllib import quote_plus


def get_engine_schema(content):
    if not content.get('QuerySource'):
        policy_type = 'managed'
        schema_expression = "list($.where($.name = '%s'))[0]" % content['RuleName']
    else:
        policy_type = 'custom'
        if content['QuerySource'] == ConnectorEngines.mongodb:
            schema_expression = "list($.where($.query_source = '%s' and $.query_source_identifier = '%s'))[0]" % (
                content['QuerySource'], content['QuerySourceIdentifier'])
        else:
            table_names = get_query_tables(content['Query'])
            schema_expression = "list($.where($.query_source = '%s' and $.query_source_identifier in %s))" % (
                content['QuerySource'], json.dumps(table_names))
    mongo_args = {'host': 'localhost', 'port': 1200, 'username': 'corestack', 'password': 'S2h4930xge5q77N', 'auth_database': 'admin'}
    db_engine_schema = get_result_from_mongo(
        mongo_args, cs_policy_storage["database"], cs_policy_storage["collection"],
        [{"$match": {"name": content['RuleName']}}])
    schema_found = db_engine_schema[0] if db_engine_schema else {}
    if not schema_found:
        engine_schema_path = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), 'data', '%s.json' % policy_type)
        with open(engine_schema_path) as f:
            coded_engine_schema = json.loads(f.read())
        schema_found = yaql.eval(schema_expression, coded_engine_schema)
    return policy_type, schema_found


def call_sql_asyn(connection_args, command):
    recv_end, send_end = multiprocessing.Pipe(False)
    p = multiprocessing.Process(target=execute_query, args=(connection_args, command, send_end))
    p.start()
    end_time = datetime.utcnow() + timedelta(minutes=5)
    while datetime.utcnow() < end_time:
        if not p.is_alive():
            p.join()
            result = recv_end.recv()
            break
        time.sleep(30)
    else:
        result = recv_end.recv()
        p.join()
    if not result['status']:
        raise Exception(result['message'])
    return result['data']


def get_result_from_sql(connection_args, command, send_end):
    try:
        driver = '{ODBC Driver 17 for SQL Server}'
        connection_string = 'DRIVER=' + driver + ';SERVER=' + connection_args['server'] + \
                            ';DATABASE=' + connection_args['database'] + ';UID=' + \
                            connection_args['user'] + ';PWD=' + connection_args['password']
        if connection_args.get('port'):
            connection_string += ';PORT=%s' % connection_args['port']
        with pyodbc.connect(connection_string, timeout=60) as conn:
            conn.timeout = connection_args.get('timeout', 300)
            with conn.cursor() as cursor:
                rows = cursor.execute(command).fetchall()
                columns = [column[0] for column in cursor.description]
                result = list()
                for row in rows:
                    result.append(dict(zip(columns, row)))
                while cursor.nextset():
                    rows = cursor.fetchall()
                    columns = [column[0] for column in cursor.description]
                    for row in rows:
                        result.append(dict(zip(columns, row)))
        send_end.send({"status": True, "data": result})
    except Exception as e:
        send_end.send({"status": False, "message": str(e)})
    send_end.close()


def get_mongo_client(connection_args):
    if connection_args.get('username') and connection_args.get('password') and connection_args.get('auth_database'):
        uri = "mongodb://%s:%s@%s:%s/%s" % (
            connection_args['username'], quote_plus(connection_args['password']),
            connection_args['host'], connection_args['port'], connection_args['auth_database'])
    else:
        uri = "mongodb://%s:%s" % (connection_args['host'], connection_args['port'])
    return MongoClient(uri)


def get_result_from_mongo(connection_args, database_name, collection_name, aggregate_query):
    client = get_mongo_client(connection_args)
    cursor = client[database_name][collection_name].aggregate(aggregate_query, cursor={}, allowDiskUse=True)
    result = [elem for elem in cursor]
    client.close()
    return result


def get_execution_parameter_required(engine_schema, execution_args, command_args_list):
    if engine_schema.get("resource_type_ref"):
        command_args_list.append("@%s='%s'" % (engine_schema['resource_type_ref'], execution_args.get("resource_type")))
    if engine_schema.get("resource_ref"):
        command_args_list.append("@%s='%s'" % (engine_schema['resource_ref'], execution_args.get("resource")))
    if engine_schema.get("assessment_ref") and execution_args.get("IsAssessment"):
        command_args_list.append("@%s=%s" % (engine_schema['assessment_ref'], execution_args.get("IsAssessment")))
    if engine_schema.get("AttributesSupported") and execution_args.get('ResourceProperties', []):
        command_args_list.append("@Attributes='%s'" % ','.join(execution_args['ResourceProperties']))
    return command_args_list


def datetime_parser(dct):
    for k, v in dct.items():
        if isinstance(v, str) and re.search(r"^\d{4}-(0[1-9]|1[012])-(0[1-9]|[12]\d|3[01])$", v):
            try:
                dct[k] = datetime.strptime(v, "%Y-%m-%d")
            except:
                pass
    return dct


def execute_query(connection_args, command, send_end):
    try:
        request_body = {"command": command}
        api_url = connection_args['execute_url']
        user = connection_args['auth_user']
        password = connection_args['auth_password']
        userAndPass = b64encode(b"" + user + ":" + password).decode("ascii")
        headers = {'Authorization': 'Basic %s' % userAndPass, 'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=request_body, verify=False)
        if response.status_code == 200:
            send_end.send({"status": True, "data": response.json()})
        else:
            send_end.send({"status": False, "message": "Failed execute query {}".format(response.content)})
    except Exception as e:
        send_end.send({"status": False, "message": str(e)})
    send_end.close()
