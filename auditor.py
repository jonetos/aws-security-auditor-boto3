import boto3
from botocore.exceptions import ClientError

def audit_security_groups():
    vulnerabilities = {"CRITICAL":[], "HIGH":[], "MEDIUM":[], "LOW":[]}
    print("[*] Initiating Security Group Audit...\n")
    
    try:
        aws_region = input("[*] Type your AWS region (e.g., us-east-1, eu-west-1): ")
        ec2_client = boto3.client('ec2', region_name=aws_region)
        
        response = ec2_client.describe_security_groups()
        
        security_groups = response.get('SecurityGroups', [])
        issues_found = 0
        
        for sg in security_groups:
            sg_name = sg.get('GroupName', 'Unnamed Security Group')
            sg_id = sg.get('GroupId', 'Unknown Group Id')
            vpc_id = sg.get('VpcId', 'Unknown VPC ID')
            
            for permission in sg.get('IpPermissions', []):
                protocol = permission.get('IpProtocol')
                match protocol:
                    case 'tcp':
                        from_port = permission.get('FromPort')
                        to_port = permission.get('ToPort')
                        
                        is_ssh_exposed = (from_port <= 22 <= to_port)
                        is_rdp_exposed = (from_port <= 3389 <= to_port)
                        is_http_exposed = (from_port <= 80 <= to_port)
                        is_db_exposed = (from_port <= 3306 <= to_port) 
        
                        for ip_range in permission.get('IpRanges', []):
                            cidr_ip = ip_range.get('CidrIp', 'Unknown CIDR')
        
                            if is_ssh_exposed and cidr_ip == '0.0.0.0/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has SSH open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                            if is_rdp_exposed and cidr_ip == '0.0.0.0/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has RDP open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                            if is_http_exposed and cidr_ip == '0.0.0.0/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has HTTP open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                            if is_db_exposed and cidr_ip == '0.0.0.0/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has DB access open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
        
                        for ip_range in permission.get('Ipv6Ranges', []):
                            cidr_ipv6 = ip_range.get('CidrIpv6', 'Unknown CIDRV6')
        
                            if is_ssh_exposed and cidr_ipv6 == '::/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has SSH open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                            if is_rdp_exposed and cidr_ipv6 == '::/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC  has RDP open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                            if is_http_exposed and cidr_ipv6 == '::/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC  has HTTP open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                            if is_db_exposed and cidr_ipv6 == '::/0':
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC  has DB access open to the entire internet."
                                issues_found += 1
                                vulnerabilities["HIGH"].append(alert)
                    case 'udp':
                        continue
                    case 'icmp':
                        for ip_range in permission.get('IpRanges', []):
                            cidr_ip = ip_range.get('CidrIp', 'Unknown CIDR')
                            if cidr_ip == "0.0.0.0/0":
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC allows ICMPv4 commands to any IPv4 address"
                                issues_found += 1
                                vulnerabilities["MEDIUM"].append(alert)
                    case 'icmpv6':
                        for ip_range in permission.get('Ipv6Ranges', []):
                            cidr_ipv6 = ip_range.get('CidrIpv6', 'Unknown CIDRv6')
                            if cidr_ipv6 == "::/0":
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC allows ICMPv6 commands to any IPv6 address"
                                issues_found += 1
                                vulnerabilities["MEDIUM"].append(alert)
                    case '-1':
                        for ip_range in permission.get('IpRanges', []):
                            cidr_ip = ip_range.get('CidrIp', 'Unknown CIDR')
                            if cidr_ip == "0.0.0.0/0":
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has every port open to the 0.0.0.0/0 ip range."
                                issues_found += 1
                                vulnerabilities["CRITICAL"].append(alert)
                        for ip_range in permission.get('Ipv6Ranges', []):
                            cidr_ip = ip_range.get('CidrIpv6', 'Unknown CIDR')
                            if cidr_ip == "::/0":
                                alert = f"The group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' VPC has every port open to the ::/0 ipv6 range."
                                issues_found += 1
                                vulnerabilities["CRITICAL"].append(alert)
                    case _:
                        alert = f"There's an alert in the group '{sg_name}' with ID '{sg_id}' in the '{vpc_id}' with an unidentified protocol({protocol}), check manually for further information"
                        issues_found += 1
                        vulnerabilities["LOW"].append(alert)

        report_name = "auditor_report.txt"
        with open(report_name, 'w') as report_file:
            report_file.write("=== AWS SECURITY AUDIT REPORT ===\n\n")
            report_file.write(f"Audited Service: AWS EC2 Security Groups\n")

            if (issues_found == 0):
                report_file.write("No vulnerabilities found.\n")
            else:
                report_file.write(f"Total vulnerabilities found: {issues_found}\n\n")
                for priority, alerts in vulnerabilities.items():
                    if(len(alerts) > 0):
                        report_file.write(f"Priority: {priority}\n")
                        for alert in alerts:
                            report_file.write(f"\t-> {alert}\n")

        print(f"\n[*] Audit completed. Report saved to '{report_name}'.")        

    except ClientError as e:
        print(f"[X] AWS Error: {e}")     

if __name__ == "__main__":
    audit_security_groups()