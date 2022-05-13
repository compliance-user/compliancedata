# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import json
import re

from bson import ObjectId

from cs_policy_interface import exceptions, validate
from cs_policy_interface.definitions import ConnectorEngines
from cs_policy_interface.exceptions import BadRequestException
from cs_policy_interface.managed_code import ManagedCode
from cs_policy_interface.utils import get_result_from_mongo, call_sql_asyn, get_execution_parameter_required, \
    datetime_parser


class Executor(object):
    def __init__(self, content, connection_args, execution_args):
        self.content = content
        self.connection_args = connection_args
        self.execution_args = execution_args
        if 'args' not in self.execution_args:
            self.execution_args['args'] = {}

    def validate(self):
        policy_type, engine_schema = validate.validate_content(self.content)
        query_source = self.content['QuerySource'] if policy_type == 'custom' else engine_schema['query_source']
        validate.validate_execution_args(self.content, self.execution_args)
        validate.validate_connection_args(query_source, self.connection_args)
        return policy_type, query_source, engine_schema

    def execute_policy(self, *args):
        try:
            policy_type, query_source, engine_schema = args
            validate.validate_execution_args(self.content, self.execution_args)
            validate.validate_connection_args(query_source, self.connection_args)
        except ValueError:
            policy_type, query_source, engine_schema = self.validate()
        try:
            service_account_id = self.execution_args['service_account_id']
            if engine_schema.get('code_ref'):
                if query_source == ConnectorEngines.mongodb:
                    self.connection_args['database_name'] = engine_schema.get('database_ref')
                violations, evaluated_resources = getattr(ManagedCode(self.execution_args, self.connection_args),
                                                          engine_schema.get('code_ref'))()
                return violations, evaluated_resources
            evaluated_resources = 0
            if query_source == ConnectorEngines.sql:
                service_account_command = "SELECT ServiceAccountID FROM report.ServiceAccount " \
                                          "WHERE isDeleted=0 AND ID='%s';" % service_account_id
                service_account_ref = call_sql_asyn(self.connection_args, service_account_command)
                if not service_account_ref:
                    raise BadRequestException('Data Not Available.')
                service_account_id = service_account_ref[0]['ServiceAccountID']
                if policy_type == 'managed':
                    command_args_list = ['@%s=%s' % (engine_schema['service_account_ref'], service_account_id)]
                    command_args_list = get_execution_parameter_required(engine_schema, self.execution_args,
                                                                         command_args_list)
                    for param_key, param_value in self.execution_args['args'].items():
                        if isinstance(param_value, list):
                            param_value = ','.join(param_value)
                        if not isinstance(param_value, str):
                            command_args_list.append("@%s=%s" % (param_key, param_value))
                        else:
                            command_args_list.append("@%s='%s'" % (param_key, param_value))
                    command_args = ', '.join(command_args_list)
                    command = 'EXEC %s %s;' % (engine_schema['query_source_identifier'], command_args)
                    result = call_sql_asyn(self.connection_args, command)
                    if result:
                        if engine_schema.get("assessment_ref") and self.execution_args.get("IsAssessment"):
                            if "TotalResourceCount" in result[-1]:
                                evaluated_resources = result[-1]["TotalResourceCount"]
                                del result[-1]
                        if result:
                            result = self.resource_id_format(result)
                else:
                    command_args = {elem['service_account_ref']: service_account_id for elem in engine_schema}
                    for param_key, param_value in self.execution_args['args'].items():
                        if isinstance(param_value, list):
                            query_param_value = ''
                            for elem in param_value:
                                query_param_value += "'%s'" % elem if isinstance(elem, str) else "%s" % elem
                            command_args[param_key] = "(%s)" % query_param_value
                        elif not isinstance(param_value, str):
                            command_args[param_key] = param_value
                        else:
                            command_args[param_key] = "'%s'" % param_value
                    command = self.content['Query'].format(**command_args)
                    result = call_sql_asyn(self.connection_args, command)
                    if result:
                        result = self.resource_id_format(result)
            else:
                match_query = engine_schema.get('default_query', {})
                service_account_ref = engine_schema['service_account_ref']
                if service_account_ref.get('key_type') == 'string':
                    match_query[service_account_ref['key_name']] = service_account_id
                else:
                    match_query[service_account_ref['key_name']] = ObjectId(service_account_id)
                if policy_type == 'custom':
                    query = self.content['Query']
                    input_parameters = self.content.get('InputParameters', {})
                else:
                    query = engine_schema['query']
                    input_parameters = engine_schema.get('input_parameters', {})
                for param_key, param_value in self.execution_args['args'].items():
                    if not (isinstance(param_value, str) and input_parameters[param_key].get('query_field')):
                        param_value = json.dumps(param_value)
                    query = re.sub(r'{%s}' % param_key, param_value, query)
                aggregate_query = json.loads(query, object_hook=datetime_parser)
                if '$match' in aggregate_query[0]:
                    aggregate_query[0]['$match'].update(match_query)
                else:
                    aggregate_query.insert(0, {'$match': match_query})
                result = get_result_from_mongo(self.connection_args, engine_schema['database_ref'],
                                               engine_schema['query_source_identifier'], aggregate_query)
            return result, int(evaluated_resources)
        except Exception:
            raise exceptions.PolicyInterfaceClientException('failed to execute the SP due to exception.')

    def resource_id_format(self, result):
        resources = dict()
        output = list()
        for violation in result:
            resource_id = violation.get("ResourceId", '')
            if resource_id and resource_id not in resources:
                resources[resource_id] = violation
        if not resources:
            return output
        # FIXME: resource_id_format should removed once all SP's are updated
        resource_name_query = "SELECT ResourceID, ResourceName, Name FROM report.ServiceResourceInventory " \
                              "WHERE ResourceID IN (%s);" % ', '.join(["'%s'" % elem for elem in resources.keys()])
        try:
            resource_name_ref = call_sql_asyn(self.connection_args, resource_name_query)
        except Exception:
            resource_name_ref = list()
        for elem in resource_name_ref:
            violation_data = resources.pop(elem['ResourceID'])
            violation_data.update(ResourceId=elem['ResourceName'])
            if elem.get('Name'):
                violation_data.update(ResourceName=elem['Name'])
            output.append(violation_data)
        for elem in resources.values():
            output.append(elem)
        return output
