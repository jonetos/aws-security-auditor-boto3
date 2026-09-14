import boto3
from botocore.exceptions import ClientError

def audit_security_groups():
    vulnerabilities = []
    print("[*] Initiating Security Group Audit...\n")
    
    try:
        aws_region = input("[*] Type your AWS region (e.g., us-east-1, eu-west-1): ")
        ec2_client = boto3.client('ec2', region_name=aws_region)
        
        response = ec2_client.describe_security_groups()
        
        security_groups = response.get('SecurityGroups', [])
        
        issues_found = 0
        
        for sg in security_groups:
            sg_name = sg.get('GroupName', 'Unnamed Security Group')
            
            for permission in sg.get('IpPermissions', []):
                
                from_port = permission.get('FromPort', -1)
                
                to_port = permission.get('ToPort', -1)
                
                is_ssh_exposed = (from_port <= 22 <= to_port) or (from_port == -1)
                is_rdp_exposed = (from_port <= 3389 <= to_port) or (from_port == -1)
                is_http_exposed = (from_port <= 80 <= to_port) or (from_port == -1)
                is_db_exposed = (from_port <= 3306 <= to_port) or (from_port == -1)

                for ip_range in permission.get('IpRanges', []):
                    cidr_ip = ip_range.get('CidrIp', 'Unknown CIDR')

                    if is_ssh_exposed and cidr_ip == '0.0.0.0/0':
                        alert = f"[!] ALERT: The group '{sg_name}' has SSH open to the entire internet."
                        issues_found += 1
                        vulnerabilities.append(alert)
                    if is_rdp_exposed and cidr_ip == '0.0.0.0/0':
                        alert = f"[!] ALERT: The group '{sg_name}' has RDP open to the entire internet."
                        issues_found += 1
                        vulnerabilities.append(alert)
                    if is_http_exposed and cidr_ip == '0.0.0.0/0':
                        alert = f"[!] ALERT: The group '{sg_name}' has HTTP open to the entire internet."
                        issues_found += 1
                        vulnerabilities.append(alert)
                    if is_db_exposed and cidr_ip == '0.0.0.0/0':
                        alert = f"[!] ALERT: The group '{sg_name}' has DB access open to the entire internet."
                        issues_found += 1
                        vulnerabilities.append(alert)

        report_name = "auditor_report.txt"
        with open(report_name, 'w') as report_file:
            report_file.write("=== AWS SECURITY AUDIT REPORT ===\n\n")
            report_file.write("Audited Service: AWS EC2 Security Groups\n")

            if(len(vulnerabilities) == 0):
                report_file.write("No vulnerabilities found.\n")

            else:
                report_file.write(f"Total vulnerabilities found: {issues_found}\n\n")
                for vulnerability in vulnerabilities:
                    report_file.write(vulnerability + "\n")

        print(f"\n[*] Audit completed. Report saved to '{report_name}'.")        

    except ClientError as e:
        print(f"[X] AWS Error: {e}")

if __name__ == "__main__":
    audit_security_groups()