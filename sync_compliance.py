import json
import shutil
import os
import sys
import traceback
from datetime import datetime
from collections import OrderedDict

from oslo_config import cfg
from ConfigParser import ConfigParser
from bson import ObjectId

possible_top_dir = os.path.normpath(
    os.path.join(
        os.path.abspath(sys.argv[0]), os.pardir, os.pardir, os.pardir))
if os.path.exists(os.path.join(possible_top_dir, 'compliance', '__init__.py')):
    sys.path.insert(0, possible_top_dir)

from compliance.core import config
from compliance.utils.short_id import str2md5
from compliance.core.log import log_setup
from compliance.core.definitions import ComplianceVars
from compliance.db.pyapi import connect_db
from compliance.utils.db_util import mongoclient
from uuid import uuid4 as uuid

from git import Repo

tenant_id = cfg.StrOpt('tenant_id')
cfg.CONF.register_cli_opt(tenant_id)
heatstack_conf = cfg.StrOpt('heatstack_conf')
cfg.CONF.register_cli_opt(heatstack_conf)

LOG = log_setup(log_filename='/var/log/corestack/compliance_sync_compliance.log')


class DictionaryWrapper(OrderedDict):
    def __missing__(self, key):
        val = self[key] = DictionaryWrapper()
        return val


def clone_controls_data(repo_url, dir_name, branch="main"):
    try:
        LOG.info('Cloning control data!!')
        if not os.path.isdir(dir_name):
            Repo.clone_from(repo_url, dir_name)
            LOG.info('Success!')
        else:
            shutil.rmtree(dir_name)
            Repo.clone_from(repo_url, dir_name)
            LOG.info('Existing data removed and new data cloned to {}'.format(dir_name))
    except Exception as e:
        LOG.error('Unable to clone compliance data from git repo')


def load_accs_master(accs_path, master_control):
    try:
        LOG.info('Loading AC3 controls in master_control collection')
        existing_controls = set([
            uri for uri in master_control.find({
                'system_default': True,
                'compliance_uri': ComplianceVars.ACCS_compliance_uri
            }).distinct('compliance_control_uri')])
        for each_file in os.listdir(accs_path):
            with open(os.path.join(accs_path, each_file), 'r') as file_content:
                load_data = json.load(file_content)
                del load_data['mode']
            load_data['created_at'] = datetime.utcnow()
            load_data['update_by'] = datetime.utcnow()
            master_controls = [load_data]
            control_list = set([
                control['compliance_control_uri'] for control in master_controls])
            new_controls = [control for control in master_controls
                            if control['compliance_control_uri'] in control_list.difference(existing_controls)]
            for control in new_controls:
                master_control.insert(control)
    except Exception as e:
        LOG.error(e)


def load_global_master(std_path, master_control):
    try:
        LOG.info('Loading global controls in master_control collection')
        existing_controls = set([
            uri for uri in master_control.find({
                'system_default': True,
                'compliance_uri': {'$ne': ComplianceVars.ACCS_compliance_uri}
            }).distinct('compliance_control_uri')])
        for each_file in os.listdir(std_path):
            with open(os.path.join(std_path, each_file), 'r') as file_content:
                load_data = json.load(file_content)
            load_data['created_at'] = datetime.utcnow()
            load_data['update_by'] = datetime.utcnow()
            master_controls = [load_data]
            control_list = set([
                control['compliance_control_uri'] for control in master_controls])
            new_controls = [control for control in master_controls
                            if control['compliance_control_uri'] in control_list.difference(existing_controls)]
            for control in new_controls:
                master_control.insert(control)
    except Exception as e:
        LOG.error(e)


def valid_services(compliance_control_definitions):
    try:
        definition = compliance_control_definitions.find({
            'scope': 'global'
        })
        valid_services = {definitions.get('compliance_uri'): definitions.get('valid_service_types')
                          for definitions in definition}
        return valid_services
    except Exception as e:
        LOG.error(e)


def default_control_mapping(master_control, compliance_control, tenant_id, compliance_uri):
    master_distinct = master_control.find({
        "compliance_uri": compliance_uri
    }).distinct("compliance_control_uri")
    control_distinct = compliance_control.find({
        "compliance_uri": compliance_uri,
        "tenant_id": tenant_id
    }).distinct("compliance_control_uri")
    difference = list(set(master_distinct).difference(control_distinct))
    results = master_control.find({
        "compliance_control_uri": {"$in": difference}
    })
    for control_record in results:
        control = DictionaryWrapper()
        control['compliance_uri'] = control_record.get("compliance_uri")
        control['compliance_control_uri'] = control_record.get("compliance_control_uri")
        control['compliance_control_number'] = control_record.get("compliance_control_number")
        control['control_attributes'] = control_record.get("control_attributes")
        control['control_action_attributes']['category'] = ""
        control['control_action_attributes']['Control Baseline'] = "Basic"
        control['control_action_attributes']['classification'] = "Process"
        control['control_action_attributes']['level'] = "Account"
        control['control_action_attributes']['nature'] = "Manual"
        control['control_action_attributes']['purpose'] = "Preventive"
        control['control_action_attributes']['action_method'] = "Document"
        control['system_default'] = True
        control['tenant_id'] = tenant_id
        control['created_at'] = datetime.utcnow()
        control['updated_at'] = datetime.utcnow()
        control['created_by'] = 'admin'
        control['update_by'] = 'admin'
        control['policy_uri'] = []
        control['is_deleted'] = False
        control['Control Name'] = control_record.get("Control Name")
        control['Control Family'] = control_record.get("Control Family")
        control['Control Statement'] = control_record.get("Control Statement", "")
        control['service_resource_mapping'] = []
        compliance_control.insert(control)


def load_compliance_control(master_control, compliance_control, tenant_id, compliance_control_definitions):
    try:
        LOG.info('Initiated compliance_control create')
        valid_service_types = valid_services(compliance_control_definitions)
        global_records = master_control.find({
            "compliance_uri": {"$ne": ComplianceVars.ACCS_compliance_uri}
        })
        for record in global_records:
            exists_already = compliance_control.find_one({
                'tenant_id': tenant_id,
                'system_default': True,
                'is_deleted': False,
                'compliance_control_uri': record['compliance_control_uri']
            })
            control_action_attribute = master_control.find_one({
                'control_control_mapping.compliance_control_mapped_uri': record['compliance_control_uri'],
                'control_action_attributes.nature': 'Automated'
            })
            if not control_action_attribute:
                control_action_attribute = master_control.find_one({
                    'control_control_mapping.compliance_control_mapped_uri': record['compliance_control_uri'],
                    'control_action_attributes.nature': 'Manual'
                })
            if not exists_already and isinstance(control_action_attribute, dict):
                data = OrderedDict()
                data['compliance_uri'] = record['compliance_uri']
                data['compliance_control_uri'] = record['compliance_control_uri']
                data['compliance_control_number'] = record['compliance_control_number']
                data['control_action_attributes'] = control_action_attribute.get('control_action_attributes', {})
                data['system_default'] = True
                data['tenant_id'] = tenant_id
                data['created_at'] = datetime.utcnow()
                data['updated_at'] = datetime.utcnow()
                data['created_by'] = 'admin'
                data['update_by'] = 'admin'
                data['policy_uri'] = list()
                data['is_deleted'] = False
                data['Control Name'] = record['Control Name']
                data['Control Family'] = record['Control Family']
                data['Control Statement'] = record['Control Statement']
                data['service_resource_mapping'] = []
                compliance_control.insert(data)
        LOG.info('Processing default control mapping')
        for compliance_uri in valid_service_types:
            default_control_mapping(master_control, compliance_control,
                                    tenant_id, compliance_uri)
    except Exception as e:
        LOG.error(e)


def get_policies(heatstack_db):
    try:
        policy_data = list(heatstack_db.policy.find({}))
        policies = []
        for policy in policy_data:
            policies.append(policy)
        return policies
    except Exception as e:
        LOG.error(e)


def post_policy_mapping_config(compliance_control_mapping,
                               compliance_control_mapping_config,
                               tenant_id,
                               compliance_control_uri_for_control,
                               get_policy_info):
    try:
        frame_mapping = OrderedDict()
        frame_config = DictionaryWrapper()
        frame_mapping['compliance_uri'] = "/".join(compliance_control_uri_for_control.split('/')[0:2])
        frame_mapping['compliance_control_uri'] = compliance_control_uri_for_control
        hash_value = frame_mapping['compliance_control_uri'] + get_policy_info.get(
            "uri") + tenant_id
        frame_mapping['compliance_control_mapping_id'] = str2md5(hash_value.encode('utf-8'))
        frame_mapping['policy_id'] = str(get_policy_info.get("_id"))
        frame_mapping['policy_name'] = get_policy_info.get("name")
        frame_mapping['policy_uri'] = get_policy_info.get("uri")
        frame_mapping['tenant_id'] = tenant_id
        frame_mapping['created_at'] = datetime.utcnow()
        frame_mapping['updated_at'] = datetime.utcnow()
        frame_mapping['created_by'] = 'admin'
        frame_mapping['update_by'] = 'admin'
        frame_mapping['is_parameterized'] = True if get_policy_info.get(
            "parameters") else False
        frame_mapping['is_deleted'] = False

        frame_config['compliance_control_uri'] = frame_mapping['compliance_control_uri']
        frame_config['compliance_control_mapping_id'] = \
            frame_mapping['compliance_control_mapping_id']
        frame_config['username'] = 'admin'
        frame_config['compliance_control_mapping_config_id'] = str(uuid())
        frame_config['account_id'] = ''
        frame_config['tenant_id'] = ObjectId(tenant_id)
        frame_config['created_at'] = datetime.utcnow()
        frame_config['updated_at'] = datetime.utcnow()
        frame_config['execution_summary']['policy_params'] = []
        frame_config['execution_summary']['policy_name'] = frame_mapping['policy_name']
        frame_config['execution_summary']['policy_uri'] = frame_mapping['policy_uri']
        frame_config['execution_summary']['policy_id'] = frame_mapping['policy_id']
        frame_config['execution_summary']['frequency'] = 'weekly'
        frame_config['is_deleted'] = False
        frame_config['to_execute'] = not frame_mapping['is_parameterized']
        exists_mapping = compliance_control_mapping.find_one({
            'tenant_id': tenant_id,
            'compliance_control_uri': frame_mapping['compliance_control_uri'],
            'policy_uri': frame_mapping['policy_uri'],
            'compliance_control_mapping_id':
                frame_mapping['compliance_control_mapping_id'],
            'is_deleted': False
        })
        if not exists_mapping:
            compliance_control_mapping.insert(frame_mapping)
            compliance_control_mapping_config.insert(frame_config)
    except Exception as e:
        LOG.error("Something went during post policy mapping and config...!")
        LOG.error(traceback.format_exc())


def create_policy_mapping(master_control,
                          compliance_control,
                          compliance_control_mapping,
                          compliance_control_mapping_config,
                          compliance_control_definitions,
                          tenant_id,
                          pol_data):
    try:
        LOG.info('Processing AC3 policy mapping...!')
        valid_service_types = valid_services(compliance_control_definitions)
        get_master_control = master_control.find({
            'compliance_uri': ComplianceVars.ACCS_compliance_uri,
            'control_action_attributes.nature': 'Automated',
            'control_policy_mapping.policy.policy_uri': {'$exists': True}
        }).distinct('compliance_control_uri')
        for control in get_master_control:
            control_with_policy_mapped = master_control.find({
                'compliance_control_uri': control
            }).distinct('control_policy_mapping.policy.policy_uri')
            if control_with_policy_mapped:
                derived_compliance_uri = "/".join(control.split('/')[0:2])
                from_service = valid_service_types.get(derived_compliance_uri), ''.join(control)
                if from_service and None not in from_service:
                    for policy_uri in control_with_policy_mapped:
                        get_policy_info = [policy_data for policy_data in pol_data
                                           if policy_uri == policy_data.get('uri')]
                        if get_policy_info and isinstance(get_policy_info[0], dict):
                            post_policy_mapping_config(compliance_control_mapping,
                                                       compliance_control_mapping_config,
                                                       tenant_id,
                                                       "".join(control),
                                                       get_policy_info[0]
                                                       )
        LOG.info('Processing global standard policy mapping...!')
        get_automated_control = compliance_control.find({
            'tenant_id': tenant_id,
            'control_action_attributes.nature': 'Automated',
            'compliance_uri': {'$ne': ComplianceVars.ACCS_compliance_uri},
            'is_deleted': False,
            'system_default': True
        }).distinct('compliance_control_uri')
        for control in get_automated_control:
            control_with_policy_mapped = master_control.find({
                'compliance_uri': ComplianceVars.ACCS_compliance_uri,
                'control_policy_mapping.policy.policy_uri': {'$exists': True},
                'control_control_mapping.compliance_control_mapped_uri': control
            }).distinct('control_policy_mapping.policy.policy_uri')
            if control_with_policy_mapped:
                derived_compliance_uri = "/".join(control.split('/')[0:2])
                from_service = valid_service_types.get(derived_compliance_uri), ''.join(control)
                if from_service and None not in from_service:
                    for policy_uri in control_with_policy_mapped:
                        get_policy_info = [policy_data for policy_data in pol_data
                                           if policy_uri == policy_data.get('uri')]
                        if get_policy_info and isinstance(get_policy_info[0], dict):
                            if len(from_service[0]) == 1 and ''.join(
                                    from_service[0]).lower() in get_policy_info[0].get('uri'):
                                post_policy_mapping_config(compliance_control_mapping,
                                                           compliance_control_mapping_config,
                                                           tenant_id,
                                                           "".join(control),
                                                           get_policy_info[0]
                                                           )
                            else:
                                if len(from_service[0]) != 1:
                                    post_policy_mapping_config(compliance_control_mapping,
                                                               compliance_control_mapping_config,
                                                               tenant_id,
                                                               "".join(control),
                                                               get_policy_info[0]
                                                               )

    except Exception as e:
        LOG.error("Error occurred during create_policy_mapping, {}".format(e.message))
        LOG.error(traceback.format_exc())


if __name__ == '__main__':
    cfg.CONF(project='compliance', prog='compliance_sync_compliance')
    config.startup_sanity_check()
    tenant_id = cfg.CONF.tenant_id
    heatstack_conf_file_path = cfg.CONF.heatstack_conf
    if not heatstack_conf_file_path:
        raise Exception(" heatstack conf file path is mandatory ")
    if not tenant_id:
        raise Exception("Tenant ID is a mandatory parameter")
    heatstack_conf = ConfigParser()
    with open(heatstack_conf_file_path, 'r') as conf:
        heatstack_conf.readfp(conf)
    heatstack_db = mongoclient(dict(heatstack_conf.items("database", raw=True)))
    client = connect_db()
    master_control = getattr(client, 'master_control')
    compliance_control = getattr(client, 'compliance_control')
    compliance_control_definitions = getattr(client, 'compliance_control_definitions')
    compliance_control_mapping = getattr(client, 'compliance_control_mapping')
    compliance_control_mapping_config = getattr(client, 'compliance_control_mapping_config')
    repo_url = 'https://github.com/compliance-user/compliancedata.git'
    dir_name = '/opt/core/Controls'
    accs_path = '/opt/core/Controls/accs_controls'
    std_path = '/opt/core/Controls/standards_json'
    pol_data = get_policies(heatstack_db)
    clone_controls_data(repo_url, dir_name)
    load_accs_master(accs_path, master_control)
    load_global_master(std_path, master_control)
    load_compliance_control(master_control, compliance_control, tenant_id,
                            compliance_control_definitions)
    create_policy_mapping(master_control,
                          compliance_control,
                          compliance_control_mapping,
                          compliance_control_mapping_config,
                          compliance_control_definitions,
                          tenant_id,
                          pol_data)
    LOG.info('All done')
