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
    accounts = []
    results = []
    try:
        results = ORG.list_accounts_for_parent(ParentId=ou_id)['Accounts']
    except ClientError as exe:
        error_and_exit('Unable to get Accounts list: ' + str(exe))
    for result in results:
        accounts.append(result['Id'])
    return accounts

def does_ou_exists(ou_object):
    '''Return True if OU exists'''

    ou_id_matched = bool(match('^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$', ou_object))
    output = True

    if not ou_id_matched:
        ou_map = get_ou_map()
        if ou_object not in ou_map.keys():
            output = False

    return output

def get_ou_map():
    '''Generate ou-id to ou-name mapping'''

    ou_list = list_all_ou()
    ou_map = {}

    for ou_item in ou_list:
        try:
            ou_describe = ORG.describe_organizational_unit(OrganizationalUnitId=ou_item)
            ou_info = ou_describe['OrganizationalUnit']
            ou_map[ou_info['Name']] = ou_info['Id']
        except ClientError as exe:
            error_and_exit('Unable to get the OU information' + str(exe))

    return ou_map

def list_all_ou():
    '''List all OUs in an organization'''

    org_info = []
    root_id = list_org_roots()
    try:
        child_dict = ORG.list_children(ParentId=root_id,
                                       ChildType='ORGANIZATIONAL_UNIT')
        child_list = child_dict['Children']
    except ClientError as exe:
        error_and_exit('Unable to get children list' + str(exe))

    while 'NextToken' in child_dict:
        next_token = child_dict['NextToken']
        try:
            child_dict = ORG.list_children(ParentId=root_id,
                                           ChildType='ORGANIZATIONAL_UNIT',
                                           NextToken=next_token)
            child_list += child_dict['Children']
        except ClientError as exe:
            error_and_exit('Unable to get complete children list' + str(exe))
    for item in child_list:
        org_info.append(item['Id'])
    if len(org_info) == 0:
        error_and_exit('No Organizational Units Found')

    return org_info

def list_org_roots():
    '''List organization roots'''

    value = None
    try:
        root_info = ORG.list_roots()
    except ClientError as exe:
        error_and_exit('Script should run on Organization root only: ' +
                       str(exe))
    if 'Roots' in root_info:
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
        LOGGER.info('\n Contact customer support with a ticket, to add the accounts to the AWS Control Tower allowed list')
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
    else:
        error_and_exit('Supplied OU does not exist.')
