# enroll-account-with-config-in-ct

This repository is hosting code for a aws blog that : Automate account enrollment with existing AWS Config into AWS Control Tower.
In this repository, we provide ressources that can simplify & automate the update of Config resources and enrol the accounts within an Organization Unit (OU) with simple steps to AWS Control Tower.

# Execution Steps:

ℹ️ If you have nested OUs, you will need to run the next 3 phases for the parent OU first and then for the nested(sub) OUs as described in the documentation.

## Phase 1:

Phase 1 consists of gathering the account IDs of the accounts that you wish to enroll to AWS Control Tower and that have existing AWS Config resources. We must contact customer support with a ticket to add the accounts to the AWS Control Tower allow list.

To fetch the above details, simply execute the script fetch-account-details.py by using your SSO administrator user.

1.	You might want to opt for one of these login options: 
a)	CloudShell: (see Getting started with AWS CloudShell)
b)	AWS SSO CLI in your local environment: (see AWS SSO CLI)
c)	Exporting the AWS SSO to your local environment: Login to SSO portal, and copy the ControlTower administrator user temporary credentials. For more details, refer to How to retrieve short-term credentials for CLI use with AWS Single Sign-on. Export user credentials. Copy and paste from the SSO portal (not needed if using CloudShell with SSO administrator user).
```
    export AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
    export AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
    export AWS_SESSION_TOKEN=<AWS_SESSION_TOKEN>
```

2.	Export the ControlTower home region (region where the CT deployed) environment variable.
```
	export AWS_DEFAULT_REGION=<Your_CT_Home_region>
```
3.	Download the script fetch-account-details.py from here (To github repo when code approved).
4.	The script needs an AWS OU ID as an input parameter. Identify the OUs that hold the accounts that have AWS Config enabled, and those must be enrolled in AWS Control Tower. Copy the OU ID from the Organization console. For more information on getting OU ID, check here.

5.	Execute the script with the following command:
```
	python3 fetch-account-details.py -o <OU ID>
```

Successful execution of the above command will print the details that you need for the support ticket.
If you have multiple OUs where AWS Config is present under their accounts, then run the above script for every OU, and continue copying the Account numbers under it. Consolidate all of these account numbers and create a single AWS Support ticket for all of the accounts. 

Once your customer support ticket has been processed, then you can proceed to Phase 2.


## Phase 2:


In this phase, we will run the Python script that will baseline the accounts and prepare them for enrollment into AWS Control Tower.
1.	We will again require fetching of the access credentials in a similar way as mentioned in Phase 1, Steps 1 and 2. 
2.	Download the script prepare_ou.py from here (To github repo when code approved).
3.	Execution of the scripts.
The script offers the Dry run mode(-d) that will print the different actions that will be performed. Note that the Dry run will deploy the “AWSControlTowerExecution” IAM role on all of the member accounts of the desired OU in order to read the details.
```
    python3 prepare_ou.py -o <OU ID> -d
```
In the case of a successful execution, the dry run will log information about the IAM roles to be deployed and AWS Config resources to be changed. If those changes are correct as per your current setup, then run the next command to make actual changes.
Execute the script with the following command (fetch the OU ID as mentioned in Phase 1, Step 5):
```
    python3 prepare_ou.py -o <OU ID>
```

In the case of a successful execution, the script will log information about the IAM roles deployed and AWS Config resource changes. If there are any errors, then the script will output the errors.

The script will take approximatively 15 seconds per region per account to run.

Once the script is executed successfully, you can move to Phase 3.


## Phase 3:

There are two ways to enroll existing accounts into AWS Control Tower governance:
1.	Register OU functionality (recommended)
2.	Enroll account by account – single account enrollment
We will discuss the Register OU method. See the single account enrolment process here.

ℹ️  As of today, you can register OUs containing up to 300 accounts (refer quota). If an OU contains over 300 accounts, then you can’t register it in AWS Control Tower. In this case, you could split the accounts in multiple OUs or nested OUs.

Log in(with SSO) to the AWS Control Tower Console using an AWS Control Tower administrator role. In the left-pane navigation menu, choose Organizational units. Select the previous OU that you baselined in Phase 2, and select Register OU.

Next, the console will provide the account list of the accounts that will enroll (under this OU), in addition to the Risks and expectations (preventive and detective guardrails that will be enabled). Agree to terms, and then select “Register OU” and start enrolling the OU.

Once the registration process is complete, you can see the enrolled status in front of all of the accounts under the registered OU. If you have nested OU underneath it, repeat the above Register OU steps like parent OU.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.