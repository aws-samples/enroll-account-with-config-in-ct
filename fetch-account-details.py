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
python fetch-account-details.py -o OU_ID

Description:
This script will fetch the details of Management account, members accounts and home region
of Control Tower for the provided OU.
'''

import logging
import sys
import argparse
from re import match
import boto3
from botocore.exceptions import ClientError

SESSION = boto3.session.Session()
CFT = SESSION.client('cloudformation')
STS = SESSION.client('sts')
ORG = SESSION.client('organizations')

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

def get_home_region():
    '''
    Relying on AWSControlTowerBP-BASELINE-CONFIG stackset
    collect Control Tower regions and Home region
    Logging and audit account ID, in addition to the s3 bucket
    '''
    home_region = None

    if does_stackset_exists('AWSControlTowerBP-BASELINE-CONFIG'):
        # Check for Stack Set
        parameters = CFT.describe_stack_set(StackSetName='AWSControlTowerBP-BASELINE-CONFIG')['StackSet']['Parameters']
        for param in parameters:
            if param['ParameterKey']=="HomeRegionName":
                home_region = param['ParameterValue']
    else:
        LOGGER.error('Unable to find CloudFormation stackset AWSControlTowerBP-BASELINE-CONFIG')
    return home_region

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fetch the details of Management account, members accounts and home region of Control Tower for the provided OU.')
    parser.add_argument("-o", "--ou", type=str, required=True, help="OU ID")

    ARGS = parser.parse_args()
    ou_id = ARGS.ou
    MASTER_ACCOUNT_ID = STS.get_caller_identity()['Account']
    accounts = []
    home_region = None

    if does_ou_exists(ou_id):
        LOGGER.info('\nContact AWS customer support with a ticket, to add the accounts to the AWS Control Tower allowed list')
        LOGGER.info('\n *** Use below text in your AWS support ticket *** \n')
        LOGGER.info('Subject Line: Enroll accounts that have existing AWS Config resources into AWS Control Tower')
        LOGGER.info('------------\n')
        LOGGER.info('Ticket body:')
        LOGGER.info('------------')
        LOGGER.info('Management account: %s', MASTER_ACCOUNT_ID)
        home_region = get_home_region()
        LOGGER.info('Control Tower Home region: %s', home_region)
        accounts = get_accounts_ou(ou_id)
        LOGGER.info('\nList of member accounts under the %s OU to be added in allowed list:', ou_id)
        print('\n'.join('{}: {}'.format(*k) for k in enumerate(accounts, start=1)))
        LOGGER.info('------------')
    else:
        error_and_exit('\n/!\ ERROR : Supplied OU does not exist.\n')
