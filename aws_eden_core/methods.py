import json
import logging
import os
import re

import boto3

from . import validators

# set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.info('Loading eden_core')

route53 = boto3.client('route53')
ecr = boto3.client('ecr')
ecs = boto3.client('ecs')
s3 = boto3.resource('s3')
elbv2 = boto3.client('elbv2')


def sanitize_string(s: str):
    return re.sub(r'([^a-zA-Z0-9_\-])', "-", s)


def sanitize_string_dns(s: str):
    return re.sub(r'([^a-zA-Z0-9_\-.])', "-", s)


def sanitize_string_alphanum_hyphen(s: str):
    return re.sub(r'([^a-zA-Z0-9\-])', "-", s)


def create_task_definition(reference_task_definition_arn: dict, target_container_name: str,
                           resource_name: str, image_uri: str):
    family = sanitize_string(resource_name)

    reference_task_definition: dict = ecs.describe_task_definition(
        taskDefinition=reference_task_definition_arn,
    )['taskDefinition']
    logger.info(f"Retrieved reference task definition from {reference_task_definition_arn}")
    logger.debug(reference_task_definition)

    container_definitions = reference_task_definition

    target_updated = False
    for definition in container_definitions['containerDefinitions']:
        if definition['name'] == target_container_name:
            definition['image'] = image_uri
            target_updated = True

    if target_updated:
        kwargs = {
            'family':               family,
            'taskRoleArn':          reference_task_definition['taskRoleArn'],
            'networkMode':          reference_task_definition['networkMode'],
            'containerDefinitions': container_definitions['containerDefinitions'],
        }

        optional_keys = [
            'executionRoleArn',
            'volumes',
            'placementConstraints',
            'requiresCompatibilities',
            'cpu',
            'memory',
            'tags',
            'pidMode',
            'ipcMode',
            'proxyConfiguration',
        ]

        for key in optional_keys:
            if key in reference_task_definition:
                kwargs[key] = reference_task_definition[key]

        logger.debug(kwargs)
        response = ecs.register_task_definition(**kwargs)
        logger.info(f"Registered new task definition: {response['taskDefinition']['taskDefinitionArn']}")
        logger.debug(response)

    else:
        raise ValueError(f"Container with name {target_container_name} not found in "
                         f"reference task definition: {reference_task_definition}")

    return response


def describe_target_group(arn: str):
    reference_target_groups = elbv2.describe_target_groups(
        TargetGroupArns=[arn],
    )
    target_group: dict = reference_target_groups['TargetGroups'][0]

    if len(reference_target_groups['TargetGroups']) == 0:
        return None

    return target_group


def describe_target_group_name(name: str):
    clean_name = sanitize_string(name)
    target_groups = elbv2.describe_target_groups(
        Names=[clean_name],
    )

    if len(target_groups['TargetGroups']) == 0:
        return None

    target_group: dict = target_groups['TargetGroups'][0]

    return target_group


def delete_target_group(name: str):
    clean_name = sanitize_string(name)
    target_group = describe_target_group_name(clean_name)

    if not target_group:
        logger.info(f"Target group {clean_name} does not exist, skipping deletion")
        return None

    response = elbv2.delete_target_group(
        TargetGroupArn=target_group['TargetGroupArn']
    )

    logger.info(f"Deleted target group {target_group['TargetGroupArn']}")

    return response


def create_target_group(reference_target_group_arn: str, resource_name: str):
    clean_resource_name = sanitize_string_alphanum_hyphen(resource_name)
    reference_target_group = describe_target_group(reference_target_group_arn)

    if not reference_target_group:
        logger.error(f"No reference target groups for ARN: {reference_target_group_arn}")
        raise ValueError(f"No reference target groups for ARN: {reference_target_group_arn}")

    logger.info(f"Retrieved reference target group: {reference_target_group_arn}")
    logger.debug(reference_target_group)

    existing_target_group = None
    try:
        existing_target_group = describe_target_group_name(clean_resource_name)

    except elbv2.exceptions.TargetGroupNotFoundException as e:
        logger.info(f"Existing target group {clean_resource_name} not found, will create new")
        logger.debug(e)

    if existing_target_group:
        logger.info(f"Target group {clean_resource_name} already exists, skipping creation")
        logger.debug(existing_target_group)
        target_group_arn = existing_target_group['TargetGroupArn']
    else:
        kwargs = {
            'Name':                       clean_resource_name,
            'Protocol':                   reference_target_group['Protocol'],
            'Port':                       reference_target_group['Port'],
            'VpcId':                      reference_target_group['VpcId'],
            'HealthCheckProtocol':        reference_target_group['HealthCheckProtocol'],
            'HealthCheckPort':            reference_target_group['HealthCheckPort'],
            'HealthCheckPath':            reference_target_group['HealthCheckPath'],
            'HealthCheckIntervalSeconds': reference_target_group['HealthCheckIntervalSeconds'],
            'HealthCheckTimeoutSeconds':  reference_target_group['HealthCheckTimeoutSeconds'],
            'HealthyThresholdCount':      reference_target_group['HealthyThresholdCount'],
            'UnhealthyThresholdCount':    reference_target_group['UnhealthyThresholdCount'],
            'Matcher':                    reference_target_group['Matcher'],
            'TargetType':                 reference_target_group['TargetType'],
        }

        optional_keys = [
            'HealthCheckEnabled',
        ]

        for key in optional_keys:
            if key in reference_target_group:
                kwargs[key] = reference_target_group[key]

        response = elbv2.create_target_group(**kwargs)
        target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
        logger.info(f"Created target group {target_group_arn}")
        logger.debug(response)

    return target_group_arn


def create_service(reference_service: dict, resource_name: str, task_definition: dict,
                   cluster_name: str, target_group_arn: dict):
    # TODO: dynamic subnet/sg ids?
    # if 'DYNAMIC_SUBNET_IDS' in os.environ:
    #     reference_service['networkConfiguration']['awsvpcConfiguration']['subnets'] = \
    #         get_variable(variables, 'DYNAMIC_SUBNET_IDS')
    #
    # if 'DYNAMIC_SECURITY_GROUP_IDS' in os.environ:
    #     reference_service['networkConfiguration']['awsvpcConfiguration']['securityGroups'] = \
    #         get_variable(variables, 'DYNAMIC_SECURITY_GROUP_IDS')

    clean_resource_name = sanitize_string_alphanum_hyphen(resource_name)

    task_definition_arn = task_definition['taskDefinition']['taskDefinitionArn']

    target_container_name: str = reference_service['loadBalancers'][0]['containerName']
    target_container_port: int = reference_service['loadBalancers'][0]['containerPort']

    kwargs = {
        'desiredCount':   reference_service['desiredCount'],
        'launchType':     reference_service['launchType'],
        'cluster':        cluster_name,
        'serviceName':    clean_resource_name,
        'taskDefinition': task_definition_arn,
        'loadBalancers':  [
            {
                'targetGroupArn': target_group_arn,
                'containerName':  target_container_name,
                'containerPort':  target_container_port
            },
        ],

    }

    optional_keys = [
        'role',
        'platformVersion',
        'placementConstraints',
        'serviceRegistries',
        'deploymentConfiguration',
        'placementStrategy',
        'networkConfiguration',
        'healthCheckGracePeriodSeconds',
        'schedulingStrategy',
        'deploymentController',
        'tags',
        'enableECSManagedTags',
    ]

    for key in optional_keys:
        if key in reference_service:
            kwargs[key] = reference_service[key]

    # describe-services may show value NONE for propagateTags,
    # however, create-service does not accept this:
    # > Propagate tags should be one of [SERVICE,TASK_DEFINITION]

    if 'propagateTags' in reference_service and reference_service['propagateTags'] != "NONE":
        kwargs['propagateTags'] = reference_service['propagateTags']

    logger.debug(f"create_service kwargs: {kwargs}")
    response = ecs.create_service(**kwargs)
    return response


def delete_service(service_name: str, cluster_name: str):
    clean_service_name = sanitize_string(service_name)
    response = ecs.delete_service(
        cluster=cluster_name,
        service=clean_service_name,
        force=True,
    )
    return response


def update_service(reference_service: dict, resource_name: str, task_definition_arn: str,
                   cluster_name: str):
    clean_resource_name = sanitize_string(resource_name)
    response = ecs.update_service(
        cluster=cluster_name,
        service=clean_resource_name,
        desiredCount=reference_service['desiredCount'],
        taskDefinition=task_definition_arn,
        deploymentConfiguration=reference_service['deploymentConfiguration'],
        networkConfiguration=reference_service['networkConfiguration'],
        platformVersion=reference_service['platformVersion'],
        forceNewDeployment=True,
        healthCheckGracePeriodSeconds=reference_service['healthCheckGracePeriodSeconds'],
    )

    return response


def config_add_env(bucket_name: str, key: str, env_name: str, env_cname: str, env_type: str, update_key: str):
    logger.info(f"Updating config file s3://{bucket_name}/{key}, "
                f"environment {env_name}: {update_key} -> {env_cname}")
    path = f"/tmp/{key}"
    s3.Bucket(bucket_name).download_file(key, path)
    with open(path, mode='r') as f:
        env_dict = json.loads(f.read())

    logger.debug(env_dict['environments'])

    updated_inplace = False
    for env in env_dict['environments']:
        if env['name'] == env_name:
            env[update_key] = env_cname
            updated_inplace = True
            logger.info(f"Existing environment found, updating in-place")
            logger.debug(env_dict['environments'])

    if not updated_inplace:
        env_dict['environments'].append(
            {
                "name":     env_name,
                "env":      env_type,
                update_key: env_cname,
            }
        )
        logger.info(f"Existing environment not found, adding new")
        logger.debug(env_dict['environments'])

    with open(path, mode='w') as f:
        f.write(json.dumps(env_dict, indent=4, sort_keys=True))

    s3.Bucket(bucket_name).upload_file(path, key)
    logger.info(f"Successfully updated config file")
    return True


def config_delete_env(bucket_name: str, key: str, env_name: str, env_cname: str, update_key: str):
    return_value = None

    logger.info(f"Updating config file s3://{bucket_name}/{key}, "
                f"delete environment {env_name}: {update_key} -> {env_cname}")
    path = f"/tmp/{key}"
    s3.Bucket(bucket_name).download_file(key, path)
    with open(path, mode='r') as f:
        env_dict = json.loads(f.read())

    for idx in range(0, len(env_dict['environments'])):
        element: dict = env_dict['environments'][idx]
        if element['name'] == env_name and update_key in element:
            logger.debug(env_dict['environments'][idx])

            minimum_keys = ["env", "name", update_key]
            if len(element.keys()) == len(minimum_keys) and all(key in element.keys() for key in minimum_keys):
                # element contains only env, name and update_key
                logger.info(f"Existing environment found, and the only optional key is {update_key},"
                            f"deleting environment")
                return_value = env_dict['environments'].pop(idx)
                break
            else:
                logger.info(f"Existing environment found, updating in-place")
                return_value = {
                    update_key: env_dict['environments'][idx][update_key]
                }
                env_dict['environments'][idx].pop(update_key)
                break

    logger.debug(return_value)

    with open(path, mode='w') as f:
        f.write(json.dumps(env_dict, indent=4, sort_keys=True))

    s3.Bucket(bucket_name).upload_file(path, key)
    logger.info(f"Successfully updated config file")
    return return_value


def describe_service(cluster_name: str, identifier: str):
    # clean_identifier = sanitize_string(identifier) <--- breaks stuff
    services = ecs.describe_services(
        services=[identifier],
        cluster=cluster_name,
    )['services']

    if len(services) == 1:
        return services[0]
    else:
        return None


def describe_alb(alb_arn):
    load_balancers = elbv2.describe_load_balancers(
        LoadBalancerArns=[alb_arn]
    )

    if len(load_balancers['LoadBalancers']) == 1:
        return load_balancers['LoadBalancers'][0]
    else:
        logger.error(f"Load balancer {alb_arn} not found")
        logger.debug(load_balancers)
        return None


def delete_alb_host_listener_rule(alb_arn: str, target_group_arn: str, domain_name: str):
    clean_domain_name = sanitize_string_dns(domain_name)

    listeners = elbv2.describe_listeners(LoadBalancerArn=alb_arn)
    logger.debug(f"listeners for alb {alb_arn}: {listeners}")

    https_listener = None
    for listener in listeners['Listeners']:
        if listener['Port'] == 443 and listener['Protocol'] == "HTTPS":
            https_listener = listener

    if not https_listener:
        logger.debug(listeners)
        raise ValueError(f"HTTPS 443 listener not found for load balancer arn: {alb_arn}")

    listener_rules = elbv2.describe_rules(ListenerArn=https_listener['ListenerArn'])
    logger.debug(f"listener rules for listener {https_listener['ListenerArn']}: {listener_rules}")

    for rule in listener_rules['Rules']:
        is_needed_target_group = False
        for action in rule['Actions']:
            if action['Type'] == "forward" and action['TargetGroupArn'] == target_group_arn:
                is_needed_target_group = True

        if not is_needed_target_group:
            continue

        for condition in rule['Conditions']:
            if condition['Field'] == "host-header" and clean_domain_name in condition['Values']:
                logger.info(f"ELBv2 listener rule for target group {target_group_arn} and host {clean_domain_name}"
                            f" found, will delete")
                response = elbv2.delete_rule(
                    RuleArn=rule['RuleArn']
                )
                return response

    logger.info(f"ELBv2 listener rule for target group {target_group_arn} and host {clean_domain_name}"
                f" does not exist, skipping deletion")
    return None


def create_alb_host_listener_rule(alb_arn: str, target_group_arn: str, domain_name: str):
    clean_domain_name = sanitize_string_dns(domain_name)

    listeners = elbv2.describe_listeners(LoadBalancerArn=alb_arn)
    logger.debug(f"listeners for alb {alb_arn}: {listeners}")

    https_listener = None
    for listener in listeners['Listeners']:
        if listener['Port'] == 443 and listener['Protocol'] == "HTTPS":
            https_listener = listener

    if not https_listener:
        logger.debug(listeners)
        raise ValueError(f"HTTPS 443 listener not found for load balancer arn: {alb_arn}")

    listener_rules = elbv2.describe_rules(ListenerArn=https_listener['ListenerArn'])
    logger.debug(f"listener rules for listener {https_listener['ListenerArn']}: {listener_rules}")

    max_priority = 0
    for rule in listener_rules['Rules']:
        if rule['Priority'] != "default" and int(rule['Priority']) > max_priority:
            max_priority = int(rule['Priority'])

        for condition in rule['Conditions']:
            if condition['Field'] == "host-header" and clean_domain_name in condition['Values']:
                logger.info(f"ELBv2 listener rule for target group {target_group_arn} already exists, "
                            f"skipping creation")
                return condition

    logger.info(f"ELBv2 listener rule for target group {target_group_arn} and host {clean_domain_name}"
                f" does not exist, will create new listener rule")

    response = elbv2.create_rule(
        ListenerArn=https_listener['ListenerArn'],
        Conditions=[
            {
                'Field':  'host-header',
                'Values': [
                    domain_name,
                ]
            },
        ],
        Priority=max_priority + 1,
        Actions=[
            {
                'Type':           'forward',
                'TargetGroupArn': target_group_arn,

            },
        ],
    )

    return response


def check_record(zone_id: str, fqdn: str):
    # maybe should check if value is record_value, type is CNAME too?

    clean_fqdn = sanitize_string_dns(fqdn)
    dotted_fqdn = clean_fqdn
    if fqdn[-1] != '.':
        dotted_fqdn += '.'

    logger.info(f"Checking if record {dotted_fqdn} exists in zone {zone_id}")

    paginator = route53.get_paginator('list_resource_record_sets')
    record_exists = False

    try:
        records = paginator.paginate(HostedZoneId=zone_id)
        for record_set in records:
            for record in record_set['ResourceRecordSets']:
                logger.debug(record)
                if record['Type'] == 'CNAME' and record['Name'] == dotted_fqdn:
                    logger.info(f"Found existing record {dotted_fqdn} in zone {zone_id}")
                    record_exists = True

    except Exception as e:
        logger.error(e)
        raise

    return record_exists


def create_cname_record(zone_id: str, record_name: str, record_value: str):
    # requires AWS ALB zone ID etc.

    clean_record_name = sanitize_string_dns(record_name)

    # TODO: create aliases to ALB instead of CNAMEs

    hosted_zone = route53.get_hosted_zone(
        Id=zone_id
    )

    logger.debug(f"Route 53 describe zone {zone_id} response: {hosted_zone}")

    if hosted_zone['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise ValueError(f"Zone not found: {zone_id}")

    # check for existing record
    if check_record(zone_id, record_name):
        logger.info(f"CNAME record already exists, skipping deletion: "
                    f"{record_name} -> {record_value}")
        return record_name

    response = route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Comment': f"Created by eden",
            'Changes': [
                {
                    'Action':            'CREATE',
                    'ResourceRecordSet': {
                        'Name':            clean_record_name,
                        'Type':            'CNAME',
                        'TTL':             60,
                        'ResourceRecords': [
                            {
                                'Value': record_value,
                            }
                        ]
                    }
                }
            ]
        }
    )

    logger.debug(response)
    logger.info(f"Successfully created CNAME: {clean_record_name} -> {record_value}")
    return clean_record_name


def delete_cname_record(zone_id: str, record_name: str, record_value: str):
    clean_record_name = sanitize_string_dns(record_name)

    hosted_zone = route53.get_hosted_zone(
        Id=zone_id
    )

    logger.debug(f"Route 53 describe zone {zone_id} response: {hosted_zone}")

    if hosted_zone['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise ValueError(f"Zone not found: {zone_id}")

    # check for existing record
    if check_record(zone_id, record_name):
        response = route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f"Created by eden",
                'Changes': [
                    {
                        'Action':            'DELETE',
                        'ResourceRecordSet': {
                            'Name':            clean_record_name,
                            'Type':            'CNAME',
                            'TTL':             60,
                            'ResourceRecords': [
                                {
                                    'Value': record_value,
                                }
                            ]
                        }
                    }
                ]
            }
        )
        logger.debug(response)
        logger.info(f"Successfully removed CNAME record {clean_record_name}")
        return response

    else:
        logger.info(f"CNAME record for {clean_record_name} does not exist, skipping deletion")
        return None


def describe_task_definitions_family(family_name, status='ACTIVE'):
    clean_family_name = sanitize_string(family_name)

    paginator = ecs.get_paginator('list_task_definitions')
    task_definitions = []

    for page in paginator.paginate(familyPrefix=clean_family_name, status=status):
        task_definitions += page['taskDefinitionArns']

    return task_definitions


def delete_task_family(family_name):
    clean_family_name = sanitize_string(family_name)

    task_definition_arns = describe_task_definitions_family(clean_family_name)

    deleted_tasks = 0
    for task_definition_arn in task_definition_arns:
        ecs.deregister_task_definition(
            taskDefinition=task_definition_arn
        )
        deleted_tasks += 1

    if deleted_tasks != len(task_definition_arns):
        raise Exception("Something bad happened")

    return deleted_tasks


def delete_env(branch, variables):
    config_s3_bucket_name: str = get_variable(variables, 'CONFIG_BUCKET')
    config_s3_key: str = get_variable(variables, 'CONFIG_BUCKET_KEY')
    config_update_key: str = get_variable(variables, 'CONFIG_UPDATE_KEY')
    config_name_prefix: str = get_variable(variables, 'CONFIG_NAME_PREFIX')
    domain_name_prefix: str = get_variable(variables, 'DOMAIN_NAME_PREFIX')
    dynamic_zone_id: str = get_variable(variables, 'DYNAMIC_ZONE_ID')
    dynamic_zone_name: str = get_variable(variables, 'DYNAMIC_ZONE_NAME').rstrip('.')
    dynamic_domain_name = f"{sanitize_string(domain_name_prefix)}-{sanitize_string(branch)}.{dynamic_zone_name}"
    config_env_name: str = f"{config_name_prefix}-{branch}"

    global_name_prefix: str = get_variable(variables, 'NAME_PREFIX')
    dynamic_resource_name: str = f"{global_name_prefix}-{branch}"

    cluster_name: str = get_variable(variables, 'TARGET_CLUSTER')

    target_alb_arn: str = get_variable(variables, 'MASTER_ALB_ARN')
    target_alb: dict = describe_alb(target_alb_arn)
    if not target_alb:
        raise ValueError(f"Load balancer not found: {target_alb_arn}")
    target_alb_domain_name: str = target_alb['DNSName']

    config_delete_env(
        config_s3_bucket_name,
        config_s3_key,
        config_env_name,
        dynamic_domain_name,
        config_update_key,
    )

    delete_cname_record(
        dynamic_zone_id,
        dynamic_domain_name,
        target_alb_domain_name,
    )

    existing_service = describe_service(cluster_name, sanitize_string_alphanum_hyphen(dynamic_resource_name))
    logger.debug(f"Looking for service named {sanitize_string_alphanum_hyphen(dynamic_resource_name)} "
                 f"in cluster {cluster_name}: "
                 f"{existing_service}")

    if existing_service:
        if existing_service['status'] == 'INACTIVE':
            logger.info(f"ECS Service {dynamic_resource_name} not found, skipping deletion")

        else:
            logger.info(f"ECS Service {dynamic_resource_name} exists, will delete")
            response = delete_service(
                dynamic_resource_name,
                cluster_name,
            )
            logger.info(f"Successfully deleted service {dynamic_resource_name} from cluster {cluster_name}")
            logger.debug(response)

    else:
        logger.info(f"ECS Service {dynamic_resource_name} not found, skipping deletion")

    try:
        dynamic_target_group_arn: str = describe_target_group_name(dynamic_resource_name)['TargetGroupArn']
        response = delete_alb_host_listener_rule(
            target_alb_arn,
            dynamic_target_group_arn,
            dynamic_domain_name
        )
        logger.debug(f"delete alb host listener response: {response}")

        response = delete_target_group(
            dynamic_resource_name
        )
        logger.debug(f"delete target group response: {response}")

    except elbv2.exceptions.TargetGroupNotFoundException:
        logger.info(f"Target group {dynamic_resource_name} not found, "
                    f"skipping deletion of listener rule and target group")

    deleted_tasks = delete_task_family(
        dynamic_resource_name,
    )
    logger.info(f"Deleted all task definitions for family: {dynamic_resource_name}, "
                f"{deleted_tasks} tasks deleted total")

    logger.info(f"Successfully finished deleting environment {dynamic_resource_name}")

    return dynamic_domain_name


def get_variable(variables, key):
    if variables is None:
        return os.environ[key]

    return variables[key]


def create_env(branch, image_uri, variables):
    config_s3_bucket_name: str = get_variable(variables, 'CONFIG_BUCKET')
    config_s3_key: str = get_variable(variables, 'CONFIG_BUCKET_KEY')
    config_update_key: str = get_variable(variables, 'CONFIG_UPDATE_KEY')
    config_name_prefix: str = get_variable(variables, 'CONFIG_NAME_PREFIX')
    config_env_type: str = get_variable(variables, 'CONFIG_ENV_TYPE')
    domain_name_prefix: str = get_variable(variables, 'DOMAIN_NAME_PREFIX')
    dynamic_zone_id: str = get_variable(variables, 'DYNAMIC_ZONE_ID')
    dynamic_zone_name: str = get_variable(variables, 'DYNAMIC_ZONE_NAME').rstrip('.')
    dynamic_domain_name = f"{sanitize_string(domain_name_prefix)}-{sanitize_string(branch)}.{dynamic_zone_name}"

    global_name_prefix: str = get_variable(variables, 'NAME_PREFIX')
    dynamic_resource_name: str = f"{global_name_prefix}-{branch}"
    config_env_name: str = f"{config_name_prefix}-{branch}"

    validators.check_image_uri(image_uri)

    cluster_name: str = get_variable(variables, 'TARGET_CLUSTER')
    reference_service_arn: str = get_variable(variables, 'REFERENCE_SERVICE_ARN')

    target_alb_arn: str = get_variable(variables, 'MASTER_ALB_ARN')
    target_alb = describe_alb(target_alb_arn)
    if not target_alb:
        raise ValueError(f"Load balancer not found: {target_alb_arn}")
    target_alb_domain_name = target_alb['DNSName']

    reference_service: dict = describe_service(
        cluster_name,
        reference_service_arn,
    )
    reference_target_group_arn: str = reference_service['loadBalancers'][0]['targetGroupArn']
    target_container_name: str = reference_service['loadBalancers'][0]['containerName']
    logger.info(f"Retrieved reference service {reference_service_arn}")
    logger.debug(reference_service)

    new_task_definition = create_task_definition(
        reference_service['taskDefinition'],
        target_container_name,
        dynamic_resource_name,
        image_uri
    )
    new_task_definition_arn = new_task_definition['taskDefinition']['taskDefinitionArn']
    logger.info(f"Registered new task definition: {new_task_definition_arn}")
    logger.debug(new_task_definition)

    new_target_group_arn = create_target_group(
        reference_target_group_arn,
        dynamic_resource_name
    )

    response = create_alb_host_listener_rule(
        target_alb_arn,
        new_target_group_arn,
        dynamic_domain_name
    )
    logger.debug(f"create alb host listener response: {response}")

    existing_service = describe_service(cluster_name, dynamic_resource_name)
    logger.debug(f"Looking for existing service named {dynamic_resource_name} in cluster {cluster_name}: "
                 f"{existing_service}")

    if existing_service:
        if existing_service['status'] == 'ACTIVE':
            logger.info(f"ECS Service {dynamic_resource_name} already exists, skipping creation")
            logger.info(f"Will deploy task definition {new_task_definition_arn} "
                        f"to service {dynamic_resource_name}")

            response = update_service(
                reference_service,
                dynamic_resource_name,
                new_task_definition_arn,
                cluster_name,
            )

            logger.info(f"Successfully deployed task definition {new_task_definition_arn} to "
                        f"service {dynamic_resource_name} in cluster {cluster_name}")
            logger.debug(response)

        else:
            logger.info(f"ECS Service {dynamic_resource_name} does not exist, will create new service")
            create_service(
                reference_service,
                dynamic_resource_name,
                new_task_definition,
                cluster_name,
                new_target_group_arn,
            )

    else:
        logger.info(f"ECS Service {dynamic_resource_name} does not exist, will create new service")
        create_service(
            reference_service,
            dynamic_resource_name,
            new_task_definition,
            cluster_name,
            new_target_group_arn,
        )

    cname = create_cname_record(
        dynamic_zone_id,
        dynamic_domain_name,
        target_alb_domain_name,
    )

    config_add_env(
        config_s3_bucket_name,
        config_s3_key,
        config_env_name,
        dynamic_domain_name,
        config_env_type,
        config_update_key,
    )

    logger.info(f"Successfully finished creating environment {dynamic_resource_name}")

    return {
        'name': dynamic_resource_name,
        'cname': cname,
    }
