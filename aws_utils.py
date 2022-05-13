# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import json
import time

import boto3
# import pyotp
import yaml
from botocore.exceptions import ClientError
from configparser import ConfigParser
from configparser import NoOptionError
from configparser import NoSectionError


def get_sts_credentials(credentials):
    retry = 5
    sleep_time = 10
    assume_role_args = dict(RoleArn=credentials['assume_role_arn'],
                            RoleSessionName=credentials['assume_role_arn'].split('/')[-1],
                            ExternalId=credentials['assume_role_external_id'])
    default_region = credentials.get('assume_role_region', 'us-east-1')
    endpoint = get_custom_endpoint_aws('sts', default_region)
    conn = boto3.client('sts', aws_access_key_id=credentials['assume_role_access_key'],
                        aws_secret_access_key=credentials['assume_role_secret_key'],
                        region_name=default_region,
                        endpoint_url=endpoint)
    if json.loads(credentials.get('assume_role_mfa_enabled', 'false')):
        assume_role_args['SerialNumber'] = credentials['assume_role_mfa_device_id']
        # assume_role_args['TokenCode'] = pyotp.TOTP(credentials['assume_role_mfa_device_secret']).now()
    while True:
        try:
            response = conn.assume_role(**assume_role_args)
            break
        except ClientError as e:
            if 'MultiFactorAuthentication failed' in str(e) and retry > 0:
                retry -= 1
                # # new_otp = pyotp.TOTP(credentials['assume_role_mfa_device_secret']).now()
                # while new_otp == assume_role_args['TokenCode']:
                #     time.sleep(sleep_time)
                #     # new_otp = pyotp.TOTP(credentials['assume_role_mfa_device_secret']).now()
                # # assume_role_args['TokenCode'] = new_otp
            else:
                raise e
    return response.get('Credentials', {})


def get_results_from_paginator(client, operation_name, operation_args, response_key):
    result = list()
    paginator = client.get_paginator(operation_name)
    page_iterator = paginator.paginate(**operation_args)
    for page in page_iterator:
        result.extend(page.get(response_key, []))
    return result


def run_aws_operation(credentials, service_name, operation_name, operation_args=None, response_key=None,
                      region_name=None, service_endpoint=None):
    cloud_type = credentials.get("cloud_type", 'aws_standard')
    if operation_args is None:
        operation_args = {}
    client_args = {
        "aws_access_key_id": credentials['access_key'],
        "aws_secret_access_key": credentials['secret_key']
    }
    if 'session_token' in credentials:
        client_args['aws_session_token'] = credentials['session_token']
    if cloud_type == "aws_gov_cloud" and not region_name:
        region_name = "us-gov-west-1"
    if region_name:
        client_args['region_name'] = region_name
        endpoint_url = get_custom_endpoint_aws(service_endpoint or service_name, region_name)
        if endpoint_url:
            client_args['endpoint_url'] = endpoint_url
    client = boto3.client(service_name, **client_args)
    try:
        if response_key and client.can_paginate(operation_name):
            return get_results_from_paginator(client, operation_name, operation_args, response_key)
        else:
            retry = 1
            while True:
                try:
                    return getattr(client, operation_name)(**operation_args)
                except Exception as e:
                    if "Throttling" in str(e):
                        if retry >= 15:
                            raise e
                        time.sleep(5 * retry)
                    else:
                        raise e
                retry += 1
    except ClientError as e:
        if '(ExpiredToken)' in str(e) or '(RequestExpired)' in str(e) or '(ExpiredTokenException)' in str(e):
            sts_credentials = get_sts_credentials(credentials)
            client_args.update(
                aws_access_key_id=sts_credentials.get('AccessKeyId'),
                aws_secret_access_key=sts_credentials.get('SecretAccessKey'),
                aws_session_token=sts_credentials.get('SessionToken')
            )
            credentials.update(
                access_key=sts_credentials.get('AccessKeyId'),
                secret_key=sts_credentials.get('SecretAccessKey'),
                session_token=sts_credentials.get('SessionToken'))
            client = boto3.client(service_name, **client_args)
            if response_key and client.can_paginate(operation_name):
                return get_results_from_paginator(client, operation_name, operation_args, response_key)
            else:
                retry = 0
                while True:
                    try:
                        return getattr(client, operation_name)(**operation_args)
                    except Exception as e:
                        if "Throttling" in str(e):
                            if retry > 10:
                                raise e
                            time.sleep(5)
                        else:
                            raise e
                    retry += 1
        raise e


def get_custom_endpoint_aws(service, region):
    custom_endpoint = None
    try:
        conf_reader = ConfigParser()
        config_content = conf_reader.read('/etc/corestack/corestack.conf')
        if config_content:
            is_vpc_enabled = json.loads(conf_reader.get('vpc_endpoint', 'enabled').lower())
            private_dns_enabled = json.loads(conf_reader.get('vpc_endpoint', 'private_dns_enabled'))
            if service == 'sts' and not region:
                # Use default region for STS service alone
                region = 'us-east-1'

            if service and region:
                if is_vpc_enabled and private_dns_enabled:
                    custom_endpoint = 'https://%s.%s.amazonaws.com' % (service, region)
                else:
                    interface_supported_endpoints = conf_reader.get('vpc_endpoint', 'interface_supported_endpoints')
                    if is_vpc_enabled and service in interface_supported_endpoints:
                        vpc_endpoint_identifier = yaml.safe_load(
                            conf_reader.get('interface_endpoint_identifier', service)).get(region)
                        if vpc_endpoint_identifier:
                            custom_endpoint = 'https://%s.%s.%s.vpce.amazonaws.com' % (
                                vpc_endpoint_identifier, service, region)
    except (NoSectionError, NoOptionError, AttributeError):
        pass
    return custom_endpoint
