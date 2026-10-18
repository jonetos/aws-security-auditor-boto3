# AWS Security Group Auditor

Python/Boto3 script that audits EC2 Security Groups in a single AWS region
and reports ingress rules exposing common ports to the whole internet.

## What it checks
Ingress rules open to `0.0.0.0/0` on:
- SSH (22), RDP (3389), HTTP (80), MySQL (3306)

Port ranges and "all traffic" rules are taken into account.

## Output
Prints alerts to the console and writes `auditor_report.txt` with the
total number of findings and one line per finding.

## Requirements
- Python 3.x and `boto3`
- AWS credentials available through the standard boto3 credential chain
  (environment variables, SSO, IAM role, or `aws configure`).
  No secrets are stored in the code.
- Minimum IAM permission (read-only): `ec2:DescribeSecurityGroups`

## Usage
python3 auditor.py
# enter the region when prompted, e.g. eu-west-1

## Known limitations
- Audits one region per run
- IPv6 (`::/0`) is not checked yet
- Reports the group name only (not the group ID)
- Does not distinguish groups attached to resources from unused ones
- Port 80 open to the world is reported although it is often intentional

## Roadmap
- IPv6 support, multi-region scan, group IDs in the report
- Severity levels, JSON/CSV output, CLI arguments
- Scheduled runs (Lambda + EventBridge) and alerts (SNS)
