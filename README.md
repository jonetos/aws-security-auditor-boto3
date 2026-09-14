# AWS Security Group Auditor 

A Python automation script leveraging the **Boto3 SDK** to audit AWS environments and detect overly permissive firewall rules. 

This tool scans all Security Groups in an AWS account and flags critical misconfigurations, such as SSH (Port 22) or RDP (Port 3389) being open to the public internet (`0.0.0.0/0`), aligning with cloud security best practices.

## Features
* **Automated Auditing:** Retrieves and parses Security Group ingress rules across the AWS account.
* **Risk Detection:** Identifies rules allowing unrestricted access to management ports.
* **Security First:** Built with principles to ensure robust infrastructure baseline security.

## Prerequisites
* Python 3.x
* AWS CLI installed and configured (`aws configure` with IAM credentials)
* `boto3` library (`pip install boto3`)

## Usage
```bash
python3 auditor.py
```
