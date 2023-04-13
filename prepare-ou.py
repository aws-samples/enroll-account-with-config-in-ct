    #
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify,merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
'''
Usage:
python prepare-accounts.py -o OU_ID [-d]

Description:
This script will populate required information of your environment.
Will update existing config according to Control Tower requirements.
This script will execute only for a single OU
'''

import logging
import re
from time import sleep
import sys
import argparse
import boto3
from botocore.exceptions import ClientError

SESSION = boto3.session.Session()
CFT = SESSION.client('cloudformation')
STS = SESSION.client('sts')
ORG = SESSION.client('organizations')
CONFIG = SESSION.client('config')

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
HANDLER = logging.StreamHandler(sys.stdout)
HANDLER.setLevel(logging.DEBUG)
LOGGER.addHandler(HANDLER)

def error_and_exit(error_msg='ERROR'):
    '''Throw error and exit'''

    LOGGER.error(error_msg)
    sys.exit(1)

def does_stackset_exists(ss_name):
    '''Return True if active StackSet exists'''
    result = False
    ss_list = []

    try:
        cft_paginator = CFT.get_paginator('list_stack_sets')
        cft_page_iterator = cft_paginator.paginate()
    except ClientError as exe:
        LOGGER.error('Unable to list stacksets %s', str(exe))

    for page in cft_page_iterator:
        ss_list += page['Summaries']

    for item in ss_list:
        if item['StackSetName'] == ss_name and item['Status'] == 'ACTIVE':
            result = True
    return result

def get_required_data():
    '''
    Relying on AWSControlTowerBP-BASELINE-CONFIG stackset
    collect Control Tower regions and Home region
    Logging and audit account ID, in addition to the s3 bucket
    '''
    region_list = []

    if does_stackset_exists('AWSControlTowerBP-BASELINE-CONFIG'):
        # Check for Stack Set
        instances = CFT.list_stack_instances(StackSetName='AWSControlTowerBP-BASELINE-CONFIG')['Summaries']
        parameters = CFT.describe_stack_set(StackSetName='AWSControlTowerBP-BASELINE-CONFIG')['StackSet']['Parameters']
        for instance in instances:
            if instance['Status'] == 'CURRENT':
                region_list.append(instance['Region'])
        for param in parameters:
            if param['ParameterKey']=="HomeRegionName" :
                home_region = param['ParameterValue']
            if param['ParameterKey']=="SecurityAccountId" :
                audit_account_id = param['ParameterValue']
            if param['ParameterKey']=="AWSLogsS3KeyPrefix" :
                aws_logs_s3_keyprefix = param['ParameterValue']
            if param['ParameterKey']=="AuditBucketName" :
                audit_bucket_name = param['ParameterValue']
                #Get Log Account number
                log_account = re.findall('\d{12}', audit_bucket_name)
    else:
        error_and_exit('\nUnable to find CloudFormation stackset AWSControlTowerBP-BASELINE-CONFIG. Make sure that you are connected using the Organization Management account')
    return list(set(region_list)), home_region, audit_account_id, aws_logs_s3_keyprefix, audit_bucket_name, log_account[0]

def get_accounts_ou(ou_id):
    '''List of accounts in an organizational unit'''
    accounts = list()
    try:
        accounts_paginator = ORG.get_paginator("list_accounts_for_parent")
        accounts_iterator = accounts_paginator.paginate(ParentId=ou_id)
    except ClientError as exe:
        LOGGER.error("Unable to get Accounts list: " + str(exe))
    for page in accounts_iterator:
        for account_info in page["Accounts"]:
            if account_info["Id"]:
                accounts.append(account_info["Id"])
    return accounts

def assume_role(account):
    """
        Assume AWSControlTowerExecution role in specified
        account and return credentials
    """
    credentials = {}
    assume_role_arn = (f'arn:aws:iam::{account}:'
                       + f'role/AWSControlTowerExecution')
    session_name = f'{account}-prepare-config'
    sts_response = STS.assume_role(
        RoleArn=assume_role_arn,
        RoleSessionName=session_name
    )
    # get new credential from STS
    credentials['session_id'] = sts_response["Credentials"]["AccessKeyId"]
    credentials['session_key'] = sts_response["Credentials"]["SecretAccessKey"]
    credentials['session_token'] = sts_response["Credentials"]["SessionToken"]
    return credentials

def list_configuration_recorders(client):
    '''List all the configuration recorders'''
    result = []
    try:
        out = client.describe_configuration_recorders()
        recorders = out['ConfigurationRecorders']
        for recorder in recorders:
            LOGGER.info('Recorder name: %s', recorder['name'])
            result.append(recorder['name'])
    except ClientError as exe:
        LOGGER.error('Unable to list Config Recorders: %s', str(exe))
    return result

def list_delivery_channels(client):
    '''List all delivery channels'''
    result = []
    try:
        out = client.describe_delivery_channels()
        channels = out['DeliveryChannels']
        for channel in channels:
            LOGGER.info('Channel name: %s', channel['name'])
            result.append(channel['name'])
    except ClientError as exe:
        LOGGER.error('Unable to list Delivery Channels: %s', str(exe))
    return result

def is_aggregation_authorization_required(client):
    '''return True if no aggregation authorizations for CT is already configured'''
    result = True
    try:
        out = client.describe_aggregation_authorizations()
        authorizations = out['AggregationAuthorizations']
        for authorization in authorizations:
            if authorization['AuthorizedAwsRegion'] == home_region and authorization['AuthorizedAccountId'] == audit_account_id:
                LOGGER.info('Config Aggregation authorization already exists in account %s in region %s.', account, region)
                result = False
    except ClientError as exe:
        LOGGER.error('Unable to list aggregation authorizations: %s', str(exe))
    return result

def create_ct_crossaccount_role(ou_id, region, master_id):
    '''
    Create cross account roles in the migrated ou using
    service managed auto deployment option of StackSets
    '''
    LOGGER.info('Creating AWSControlTowerExecution IAM role under all accounts of OU: %s', ou_id)
    ss_bucket = 'marketplace-sa-resources.s3.amazonaws.com/ct-blogs-content'
    ss_url = 'https://' + ss_bucket + '/AWSControlTowerExecution.yml'
    ss_deploy = {'Enabled': True, 'RetainStacksOnAccountRemoval': True}
    ss_name = 'CTExecutionRole-StackSet-' + ou_id
    ss_param = [{'ParameterKey': 'AdministratorAccountId', 'ParameterValue': master_id}]
    capabilities = ['CAPABILITY_NAMED_IAM']
    result = False
    op_id = None
    ss_status = 'RUNNING'

    try:
        result = CFT.create_stack_set(StackSetName=ss_name,
                                      Description='AWSControlTowerExecution cross account role creation for OU',
                                      TemplateURL=ss_url,
                                      Capabilities=capabilities,
                                      Parameters=ss_param,
                                      PermissionModel='SERVICE_MANAGED',
                                      AutoDeployment=ss_deploy)
    except ClientError as exe:
        error_msg = str(exe.response['Error']['Message'])
        if 'StackSet already exists' in error_msg:
            LOGGER.info('StackSet already exists, Adding stack instance')
            result = True
        else:
            raise exe
    if result:
        op_id = add_stack_instance(ss_name, region, ou_id)

    # Wait for cross-account role creation completion
    while ss_status in ('RUNNING', 'QUEUED', 'STOPPING'):
        LOGGER.info('Creating cross-account roles wait 20 sec: %s',
                    ss_status)
        ss_status = check_ss_status(ss_name, op_id)
        sleep(20)
    result = bool(ss_status in ('SUCCEEDED', 'FAILED'))

    return result

def add_stack_instance(ss_name, region_name, ou_id):
    '''Add stack instance to the existing StackSet'''

    targets = {'OrganizationalUnitIds': [ou_id]}
    result = {'OperationId': None}
    op_prefer = {'FailureTolerancePercentage': 100}
    output = does_stack_set_exists(ss_name)

    if output:
        try:
            result = CFT.create_stack_instances(StackSetName=ss_name,
                                                Regions=[region_name],
                                                DeploymentTargets=targets,
                                                OperationPreferences=op_prefer)
        except ClientError as exe:
            error_msg = str(exe.response['Error']['Message'])
            LOGGER.info('add_stack_instance - Error: ' + error_msg)
            raise exe
    else:
        LOGGER.error('StackSet %s does not exist', ss_name)

    return result['OperationId']

def does_stack_set_exists(ss_name):
    '''Return True if active StackSet exists'''
    result = False
    ss_list = []

    try:
        cft_paginator = CFT.get_paginator('list_stack_sets')
        cft_page_iterator = cft_paginator.paginate()
    except ClientError as exe:
        LOGGER.error('Unable to list stacksets %s', str(exe))
    for page in cft_page_iterator:
        ss_list += page['Summaries']
    for item in ss_list:
        if item['StackSetName'] == ss_name and item['Status'] == 'ACTIVE':
            result = True

    return result

def check_ss_status(ss_name, op_id):
    '''Return true on successful deployment of stack instance'''

    try:
        result = CFT.describe_stack_set_operation(StackSetName=ss_name,
                                                  OperationId=op_id)
    except ClientError as exe:
        LOGGER.error('Something went wrong: %s', str(exe))
        result = None
    if result:
        result = result['StackSetOperation']['Status']

    return result

def get_sts_session(account_number, external_id):
    '''
    Assumes the provided role in each account and returns a session object
    :param account_number: AWS Account Number
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    '''
    response = try_assume_role(account_number, 'AWSControlTowerExecution', external_id)

    if 'Credentials' in response:
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        return sts_session

def try_assume_role(account_number, role_name, external_id):
    '''Return STS keys on success and Error on failure'''

    partition = STS.get_caller_identity()['Arn'].split(":")[1]
    role_arn = 'arn:{}:iam::{}:role/{}'.format(partition,
                                               account_number,
                                               role_name)
    result = dict()
    try:
        result = STS.assume_role(
            RoleArn=role_arn,
            RoleSessionName=str(account_number + '-' + role_name),
            ExternalId=external_id)
    except ClientError as exe:
        if str(exe.response['Error']['Code']) == 'AccessDenied':
            result = exe.response
        else:
            result['Error']['Reason'] = str(exe)
    return result

def get_org_id():
    '''Get organization id'''

    try:
        value = ORG.describe_organization()['Organization']['Id']
        return value
    except ClientError as exe:
        error_and_exit('Unable to get organization id: ' + str(exe))

def does_ou_exists(ou_object):
    '''Return True if OU exists'''

    output = True
    root_id = list_org_roots()
    ou_ids = get_ou_ids(root_id)
    if ou_object not in ou_ids:
        output = False

    return output

def get_ou_ids(parent_id):
    ''' Return a list of all OU ID including nested OU'''
    full_result = []

    try:
        paginator = ORG.get_paginator('list_children')
        iterator  = paginator.paginate(
            ParentId=parent_id,
            ChildType='ORGANIZATIONAL_UNIT'
        )
    except ClientError as exe:
        error_and_exit('\nUnable to paginate on list_childrenpplied OU.() of su')
    for page in iterator:
        for ou in page['Children']:
            full_result.append(ou['Id'])
            full_result.extend(get_ou_ids(ou['Id']))

    return full_result

def list_org_roots():
    '''List organization roots'''
    value = None
    try:
        root_info = ORG.list_roots()
    except ClientError as exe:
        error_and_exit('Script should run on Organization root only: ' +
                       str(exe))
    if 'Roots' in root_info and len(root_info) > 0:
        value = root_info['Roots'][0]['Id']
    else:
        error_and_exit('Unable to find valid root: ' + str(root_info))

    return value

def stack_exists(name, region, session):
    '''Check if CloudFormation stack exists '''
    try:
        client = session.client('cloudformation', region_name=region)
        data = client.describe_stacks(StackName=name)

    except ClientError as exe:
        return False

    return data['Stacks'][0]['StackStatus'] == 'CREATE_COMPLETE'

def iam_role_exists(name, session):
    '''Check if IAM role exists '''
    try:
        client = session.client('iam')
        response = client.get_role(RoleName=name)

    except ClientError as exe:
        error_msg = str(exe.response['Error']['Message'])
        return False

    if response:
        return True

def create_config_recorder_role(session, account, home_region):
    '''Update Config recorder IAM role'''
    LOGGER.info('Creating Config recorder role in account : %s', account)
    client = session.client('cloudformation', region_name=home_region)

    s_name = 'CustomerCreatedConfigRecorderRoleForControlTower'
    role_name='aws-controltower-ConfigRecorderRole-customer-created'
    stack_present = False
    role_present = False

    stack_present = stack_exists(s_name, home_region, session)
    role_present = iam_role_exists(role_name, session)

    #When CloudFormation stack and role does not exist, create one
    if not stack_present and not role_present:
        s_bucket = 'marketplace-sa-resources.s3.amazonaws.com/ct-blogs-content'
        s_url = 'https://' + s_bucket + '/CustomerCreatedConfigRecorderRoleForControlTower.yml'
        capabilities = ['CAPABILITY_NAMED_IAM']

        try:
            result = client.create_stack(StackName=s_name,
                                          TemplateURL=s_url,
                                          Capabilities=capabilities
                                        )
            # wait until stack creates role
            sleep(30)
        except ClientError as exe:
            error_msg = str(exe.response['Error']['Message'])
            error_and_exit('Error in account ' + account + ' while creation of config recorder role stack. Error : ' + error_msg)
    else:
        LOGGER.info('Config recorder role and/or stack exists. Skipping account %s for Config recorder role creation', account)

def update_config_recorder(session, account, region, config_recorder_name):
    '''Update Config recorder'''
    client = session.client('config', region_name=region)
    result = False
    #Setting GLOBAL_CONFIGURATION_RECORDER to False
    GCR = False
    
    if region == home_region:
        GCR = True

    role_arn = 'arn:aws:iam::'+account+':role/aws-controltower-ConfigRecorderRole-customer-created'
    try:
    
        response = client.put_configuration_recorder(
            ConfigurationRecorder={
                'name': config_recorder_name,
                'roleARN': role_arn,
                'recordingGroup': {
                    'allSupported': True,
                    'includeGlobalResourceTypes': GCR,
                'resourceTypes': []
                }
            }
        )
    except ClientError as exe:
        error_msg = str(exe.response['Error']['Message'])
        error_and_exit('Config recorder modification failed for account %s in region %s. Error: %s', account, region, error_msg)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        LOGGER.info('Config recorder modified successfully in account %s in regions %s.', account, region)
        result = True

    return result

def update_config_channel(session, account, region, config_channel_name, log_bucketname, aws_logs_s3_keyprefix):
    '''Update Config channel'''
    client = session.client('config', region_name=region)
    result = False

    sns_topic_arn = 'arn:aws:sns:'+region+':'+audit_account_id+':aws-controltower-AllConfigNotifications'
    try:
        chan_res = client.put_delivery_channel(
            DeliveryChannel={
                'name': config_channel_name,
                's3BucketName': log_bucketname,
                's3KeyPrefix': aws_logs_s3_keyprefix,
                'snsTopicARN': sns_topic_arn,
                'configSnapshotDeliveryProperties': {
                    'deliveryFrequency': 'TwentyFour_Hours'
                }
            }
        )
    except ClientError as exe:
        error_msg = str(exe.response['Error']['Message'])
        error_and_exit('Config channel modification failed for account {1} in region {1}. Error: {2}'.format(account, region, error_msg))
    if chan_res['ResponseMetadata']['HTTPStatusCode'] == 200:
        LOGGER.info('Config channel modified successfully in account %s in regions %s.', account, region)
        result = True

    return result

def create_aggregation_authorization(session, audit_account_id, home_region):
    '''Crate aggregation authorizations'''
    client = session.client('config', region_name=region)
    result = False
    audit_acc = audit_account_id
    home_reg = home_region

    try:
        response = client.put_aggregation_authorization(
            AuthorizedAccountId=audit_acc,
            AuthorizedAwsRegion=home_reg
        )
    except ClientError as exe:
        error_msg = str(exe.response['Error']['Message'])
        error_and_exit('Config AggregationAuthorization creation failed for account {1} in region {1}. Error: {2}'.format(account, region, error_msg))

    if response['AggregationAuthorization']['AggregationAuthorizationArn']:
        LOGGER.info('Config Aggregation Authorization created successfully in account %s in regions %s.', account, region)
        result = True

    return result

def list_aggregation_authorizations(client):
    '''List all aggregation authorizations'''

    result = []

    try:
        out = client.describe_aggregation_authorizations()
        authorizations = out['AggregationAuthorizations']
        for authorization in authorizations:
            result.append(authorization['AggregationAuthorizationArn'])
    except ClientError as exe:
        LOGGER.error('Unable to list aggregation authorizations: %s', str(exe))

    return result

def create_config_resources(region, master_id, account):
    '''
    Create Config resources in to be migrated accounts using StackSets
    '''
    LOGGER.info('Config resources does not exists in ControlTower governed region %s. Creating Config resources in account %s...', region, account)
    ss_bucket = 'marketplace-sa-resources.s3.amazonaws.com/ct-blogs-content'
    ss_url = 'https://' + ss_bucket + '/CTConfigResources_v2.yml'
    ss_name = 'CTConfigResources-StackSet'
    
    #Setting GLOBAL_CONFIGURATION_RECORDER to False
    GCR = "false"
    
    ss_param = [{'ParameterKey': 'LoggingAccount', 'ParameterValue': log_account},
                {'ParameterKey': 'HomeRegion', 'ParameterValue': home_region},
                {'ParameterKey': 'OrganizationID', 'ParameterValue': AWSLogsS3KeyPrefix},
                {'ParameterKey': 'AuditAccount', 'ParameterValue': audit_account_id},
                {'ParameterKey': 'GlobalConfigurationRecorder', 'ParameterValue': GCR}]
                
    result = "False"
    op_id = None
    ss_status = 'RUNNING'

    try:
        result = CFT.create_stack_set(StackSetName=ss_name,
                                      Description='Config resources creation in account where its not present',
                                      TemplateURL=ss_url,
                                      AdministrationRoleARN='arn:aws:iam::'+master_id+':role/service-role/AWSControlTowerStackSetRole',
                                      ExecutionRoleName='AWSControlTowerExecution',
                                      Parameters=ss_param,
                                      PermissionModel='SELF_MANAGED')
    except ClientError as exe:
        error_msg = str(exe.response['Error']['Message'])
        if 'StackSet already exists' in error_msg:
            LOGGER.info('StackSet already exists, Adding stack instance')
            result = True
        else:
            raise exe

    if result:
        op_id = add_config_stack_instance(ss_name, region, account)

    # Wait for resources creation completion
    while ss_status in ('RUNNING', 'QUEUED', 'STOPPING'):
        LOGGER.info('Creating config resources, wait 20 sec: %s',
                    ss_status)
        ss_status = check_ss_status(ss_name, op_id)
        sleep(20)

    if ss_status == "FAILED" :
        error_and_exit('\nUnable to create Config resources in the account : %s  and region : %s', account, region)
        
        
    if region == home_region:
        GCR = "true"
        print("In home region....\n")
        try:
            param_overrides = [{'ParameterKey': 'LoggingAccount', 'ParameterValue': log_account},
                    {'ParameterKey': 'HomeRegion', 'ParameterValue': home_region},
                    {'ParameterKey': 'OrganizationID', 'ParameterValue': AWSLogsS3KeyPrefix},
                    {'ParameterKey': 'AuditAccount', 'ParameterValue': audit_account_id},
                    {'ParameterKey': 'GlobalConfigurationRecorder', 'ParameterValue': GCR}]
                    
            # OperationPreferences = {
            #         'RegionConcurrencyType': 'PARALLEL'
            #     }
                    
            result = CFT.update_stack_instances(StackSetName=ss_name,
                                          Accounts=[account],
                                          Regions=[region],
                                          ParameterOverrides=param_overrides)
                                        #   OperationPreferences=OperationPreferences)
                                          
        except ClientError as exe:
            error_msg = str(exe.response['Error']['Message'])
            if 'Update of stack set failed in home_region with :' in error_msg:
                LOGGER.info('Update of Config resource stack set failed in home region %s', home_region)
                result = True
            else:
                raise exe
        
        op_id = result['OperationId']
        ss_status = 'RUNNING'
        # Wait for resources update completion
        while ss_status in ('RUNNING', 'QUEUED', 'STOPPING'):
            LOGGER.info('Updating config resource stack in home region, wait 20 sec: %s',
                        ss_status)
            ss_status = check_ss_status(ss_name, op_id)
            sleep(20)
    
        if ss_status == "FAILED" :
            error_and_exit('\nUnable to update Config resource in the account : %s  and in home region : %s', account, region)

def add_config_stack_instance(ss_name, region_name, account):
    '''Add stack instance to the existing StackSet'''

    targets = {'Accounts': [account]}
    result = {'OperationId': None}
    op_prefer = {'FailureTolerancePercentage': 100}
    output = does_stack_set_exists(ss_name)

    if output:
        try:
            result = CFT.create_stack_instances(StackSetName=ss_name,
                                                Regions=[region_name],
                                                DeploymentTargets=targets,
                                                OperationPreferences=op_prefer)
        except ClientError as exe:
            error_msg = str(exe.response['Error']['Message'])
            LOGGER.info('add_stack_instance - Error: %s ', error_msg)
            raise exe
    else:
        LOGGER.error('StackSet %s does not exist', ss_name)
    return result['OperationId']


if __name__ == '__main__':
    '''Main function to execute script'''

    parser = argparse.ArgumentParser(description='Prepare aws accounts that have existing config ressources within an OU to be governed by AWS Control Tower')
    parser.add_argument("-o", "--ou", type=str, required=True, help="OU ID")
    parser.add_argument("-d", "--dry_run", action='store_true', help="Dry run only. No account Config resources updated.")

    ARGS = parser.parse_args()
    ou_id = ARGS.ou
    dry_run = ARGS.dry_run

    MASTER_ACCOUNT_ID = STS.get_caller_identity()['Account']
    USER_ROLE = STS.get_caller_identity()['Arn'].split(':')[-1]
    LOGGER.info('-----------------------------------------------------------------------------------')
    LOGGER.info('Executing on AWS Account ID: %s with user/role: %s', MASTER_ACCOUNT_ID, USER_ROLE)
    LOGGER.info('-----------------------------------------------------------------------------------')
    LOGGER.info('-------- Summary of the ControlTower environment ---------')
    region_list, home_region, audit_account_id, AWSLogsS3KeyPrefix, LogBucketName, log_account = get_required_data()
    LOGGER.info('Control Tower Governed regions : %s', region_list)
    LOGGER.info('Control Tower Home region : %s', home_region)
    LOGGER.info('Control Tower AWSLogsS3KeyPrefix : %s', AWSLogsS3KeyPrefix)
    LOGGER.info('Control Tower Log Bucket Name : %s', LogBucketName)
    LOGGER.info('Control Tower Audit account id : %s', audit_account_id)
    LOGGER.info('Control Tower Log account id : %s', log_account)

    if does_ou_exists(ou_id):
        accounts = get_accounts_ou(ou_id)
        if len(accounts) > 0 :
            LOGGER.info('--- List of accounts under the supplied OU : %s ---', ou_id)
            print('\n'.join('{}: {}'.format(*k) for k in enumerate(accounts, start=1)))
        else:
            error_and_exit('\nSupplied OU doesn\'t have member accounts.')
    else:
        error_and_exit('Supplied OU does not exist.')

    LOGGER.info('-----------------------------------------------------------------------------------\n')

    #Create Control Tower execution role
    create_ct_crossaccount_role(ou_id, home_region, MASTER_ACCOUNT_ID)

    # Dry run to list the Config changes
    if dry_run:
        LOGGER.info('\n#########################  DRY RUN MODE  ##############################\n')
        for account in accounts:
            LOGGER.info('******************** These Config resources in account : %s are expected to be updated. ********************\n',account)
            session = get_sts_session(account, get_org_id())
            if session:
                for region in region_list:

                    LOGGER.info('Listing in %s region :', region)
                    client = session.client('config', region_name=region)
                    ##### List Config recorders
                    config_recorders = list_configuration_recorders(client)
                    REC_LENGTH = len(config_recorders)

                    ##### List Config channels
                    delivery_channels = list_delivery_channels(client)
                    CHAN_LENGTH = len(delivery_channels)

                    ##### Check aggregation authorizations
                    list_aggregation_authorizations(client)
                    if is_aggregation_authorization_required(client) and (REC_LENGTH > 0 and CHAN_LENGTH > 0):
                        LOGGER.info('Config aggregation authorization is required & will be created.')

                    ##### when no Config resources deployed in CT governed region
                    if REC_LENGTH == 0 and CHAN_LENGTH == 0:
                        LOGGER.info('Config is not present. New Config resources will be created according to Control Tower`s requirement.')
                    LOGGER.info('----------------------------------------------------------------------')
        LOGGER.info('--- End of accounts in supplied OU ---')
        quit()

    # Update the Config resources
    for account in accounts:
        LOGGER.info('###############  Updating Config Resources  ###############')
        LOGGER.info('\n******************** Executing in account : %s ********************', account)
        session = get_sts_session(account, get_org_id())
        if session:
            create_config_recorder_role(session, account, home_region)

        for region in region_list:
            LOGGER.info('--------------------- Updating config ressources in region : %s-----------------------', region)
            client = session.client('config', region_name=region)
            ##### Update Config recorders
            config_recorders = list_configuration_recorders(client)
            REC_LENGTH = len(config_recorders)
            if REC_LENGTH > 0:
                recorder_name = config_recorders[0]
                update_config_recorder(session, account, region, recorder_name)
            else:
                LOGGER.info('No Config recorder exists in account %s in region %s.', account, region)

            ##### Update Config channels
            delivery_channels = list_delivery_channels(client)
            CHAN_LENGTH = len(delivery_channels)
            if CHAN_LENGTH > 0:
                channel_name = delivery_channels[0]
                update_config_channel(session, account, region, channel_name, LogBucketName, AWSLogsS3KeyPrefix)
            else:
                LOGGER.info('No Config delivery channel exists in account %s in region %s.', account, region)
                if REC_LENGTH > 0:
                    channel_name = "aws-controltower-BaselineConfigDeliveryChannel-customer-created"
                    update_config_channel(session, account, region, channel_name, LogBucketName, AWSLogsS3KeyPrefix)
                    LOGGER.info('Config delivery channel created in account %s in region %s.', account, region)

            ##### Create Config Aggregation authorization
            if is_aggregation_authorization_required(client) and (REC_LENGTH > 0 and CHAN_LENGTH > 0):
                LOGGER.info('No Aggregation authorization found, Creating... ')
                create_aggregation_authorization(session, audit_account_id, home_region)

            ##### when no Config resources deployed in CT governed region, deploy them.
            if REC_LENGTH == 0 and CHAN_LENGTH == 0:
                create_config_resources(region, MASTER_ACCOUNT_ID, account)
    LOGGER.info('--- End of accounts in supplied OU ---')
