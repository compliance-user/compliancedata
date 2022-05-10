from cs_policy_interface.client import Executor
from cs_policy_interface.validate import validate_content

raw_content = {
  "Version": "1.0",
  "RuleName": "AWS_CLOUD_FRONT_PROTOCOL_POLICY_DOES_NOT_ENFORCE_HTTPS_ONLY",
  "InputParameters": {
  }
}

connection_args = {
    # MongoDB
    "host": "<host>>",
    "port": "27017"
    # SQL
    # "server": '<server>',
    # "user": '<username>',
    # "password": '<password>',
    # "database": '<database_schema>',
    # "port": '1433'
}

execution_args = {
    "resource_type": 'CloudTrail',
    "resource": 'Trail',
    "service_account_id": '60f17578dbd2eac5649ee4c9',
    "service_account_name": 'Siva',
    "args": {
    },
    "approved_ami": {"ami-06fb5332e8e3e577a", "ami-0fed77069cd5a6d6c"},
    "list_metrics": {"Invocation4XXErrors","Invocation5XXErrors","ModelLatency","ModelLoadingWaitTime","ModelLoadingTime","CPUUtilization","MemoryUtilization","GPUUtilization","GPUMemoryUtilization","DiskUtilization","JobsFailed","JobsStopped","TasksDeclined","TimeSpent","ExecutionFailed","ExecutionStopped","StepFailed","StepStopped"},
    "list_namespaces": {"aws/sagemaker/ProcessingJobs", "aws/sagemaker/TrainingJobs", "aws/sagemaker/TransformJobs", "aws/sagemaker/Endpoints"},
    "IsAssessment": 1,
    "auth_values":
        {"access_key": "",
         "secret_key": ""},
    "valid_instance_type" : {'cache.t3.micro', 'cache.t3.small', 'cache.t3.medium'},
    "memcached_version": '1.6.8',
    "redis_version" : '7.2.5'
}

policy_type, query_source, engine_schema = validate_content(raw_content)
policy_violations, evaluated_resources = Executor(raw_content, connection_args, execution_args).execute_policy(
    policy_type, query_source, engine_schema)

print(policy_violations)
print(evaluated_resources)
