# AWS Security Group Auditor

Python/Boto3 script that audits the inbound rules of EC2 Security Groups in a
single AWS region and reports the ones exposed to the whole internet.

## What it checks

An inbound rule is flagged only if its source is `0.0.0.0/0` (IPv4) or `::/0` (IPv6).

| Rule type | Finding | Severity |
|---|---|---|
| All traffic (`-1`) | Every port open to the internet | CRITICAL |
| TCP covering SSH (22), RDP (3389), HTTP (80) or MySQL (3306) | Port exposed (single ports and ranges) | HIGH |
| ICMP / ICMPv6 | Ping and other ICMP allowed from anywhere | MEDIUM |
| Unrecognized protocol | Needs manual review | LOW |

UDP rules are ignored on purpose: the audited services run over TCP.
Rules whose source is a specific IP range or another security group are not flagged.

## Output
Writes `auditor_report.txt` with the total number of findings, grouped by severity.
Each finding includes the group name, group ID and VPC ID.

## Requirements
- Python 3.10+ (uses `match`); tested on Python 3.12.3 and `boto3`
- AWS credentials through the standard boto3 credential chain (environment
  variables, shared config profiles, SSO or an IAM role). No secrets in the code.
- Minimum IAM permission (read-only): `ec2:DescribeSecurityGroups`

## Setup
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

## Usage
```
python3 auditor.py
```
Enter the region when prompted (e.g. `us-east-1`). To use a named profile:
```
AWS_PROFILE=auditor python3 auditor.py
```

## Testing
Manually tested against one security group per case: all traffic, all TCP ports,
SSH open over IPv4, SSH open over IPv6, ICMP, ICMPv6, ICMP restricted to a /32,
UDP on port 22, and the default security group. Expected result: 9 findings.
The script was also run with a user holding only `ec2:DescribeSecurityGroups`;
other EC2 actions return `UnauthorizedOperation`.

## Known limitations
- One region per run
- Only inbound rules are audited (egress is not checked)
- Only four ports are checked, and only over TCP
- Rules that reference another security group as the source are not evaluated
- Does not check whether a group is attached to any resource, so unused and
  in-use groups are reported the same way
- HTTP (80) open to the world is flagged even though it is often intentional
- Duplicated logic across the rule checks; findings are plain strings

## Roadmap
- Check whether each group is in use (e.g. via network interfaces)
- Refactor: ports as data and findings as structured records
- Scan all regions (needs `ec2:DescribeRegions`)
- JSON/CSV output
- Run through an assumed IAM role (temporary credentials) instead of a user