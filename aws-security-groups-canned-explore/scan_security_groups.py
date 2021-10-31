"""
This script does the following for each AWS EC2 region:

1. Find security groups across all AZs.
2. For security group in each AZ - find resources with which this security
   group is assicated.
3. Dump details like VPC, security group id, assocations, etc. in a csv format

"""

import os
import argparse
import csv
import io
import json
import sys
import ipaddress
import requests
import boto3

ec2 = boto3.client("ec2")


def get_aws_regions():
    """Get AWS regions"""
    response = ec2.describe_regions()
    return sorted([x["RegionName"] for x in response["Regions"]])


def load_args():
    """Load cli args"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--regions", nargs="+", help="AWS regions")
    parser.add_argument("--use-cache", dest="use_cache", action="store_true", help="Use cached output")
    parser.add_argument("--org-ip-addr-file", default=None, help="Use org whitelisted ip addrs")
    parser.add_argument("--ext-ip-addr-file", default=None, help="Use external whitelisted ip addrs")

    args = vars(parser.parse_args(sys.argv[1:]))

    if args["org_ip_addr_file"]:
        if not os.path.exists(args["org_ip_addr_file"]):
            sys.stderr.write(f'ERROR: --org-ip-addr-file: {args["org_ip_addr_file"]} does not exist')
            sys.exit(1)

    if args["ext_ip_addr_file"]:
        if not os.path.exists(args["ext_ip_addr_file"]):
            sys.stderr.write(f'ERROR: --ext-ip-addr-file: {args["ext_ip_addr_file"]} does not exist')
            sys.exit(1)

    all_regions = get_aws_regions()
    if args["regions"] is None:
        args["regions"] = all_regions

    invalid_regions = []
    if args["regions"]:
        invalid_regions = [x for x in args["regions"] if x not in all_regions]

    if invalid_regions:
        sys.stderr.write(f"ERROR: Invalid regions specified - {invalid_regions}")
        sys.exit(1)

    return args


def get_derived_ip_ranges(args):
    """Get security approved allowed IP CIDRs"""
    sys.stderr.write("STATUS: Getting allowed IP ranges\n")

    ip_ranges = {"org": [], "default_vpc": [], "vpc": [], "aws": [], "ext": []}
    org_ip_addr_file = args["org_ip_addr_file"]
    ext_allowed_ip_addr_file = args["ext_ip_addr_file"]

    if org_ip_addr_file:
        org_allowed_ds = json.loads(open(org_ip_addr_file).read())
        for ip_addr in org_allowed_ds:
            ip_ranges["org"].append(ip_addr)

    aws_ip_ranges_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    resp = requests.get(aws_ip_ranges_url)
    if resp.status_code != 200:
        sys.stderr.write("ERROR: Failed to find AWS allowed IP addrs - " + aws_ip_ranges_url)
    aws_allowed_ds = resp.json()
    ip_ranges["aws"].extend([x["ip_prefix"] for x in aws_allowed_ds["prefixes"]])

    if ext_allowed_ip_addr_file:
        ext_allowed_ds = json.loads(open(ext_allowed_ip_addr_file).read())
        for ip_addr in ext_allowed_ds:
            ip_ranges["ext"].append(ip_addr)

    for region in args["regions"]:
        sys.stderr.write("STATUS: Checking region - %s - get vpc ips\n" % region)
        region_ec2 = boto3.client("ec2", region_name=region)
        response = region_ec2.describe_vpcs()
        for vpc_ds in response["Vpcs"]:
            if vpc_ds.get("IsDefault", False):
                ip_ranges["default_vpc"].append(vpc_ds["CidrBlock"])
            else:
                ip_ranges["vpc"].append(vpc_ds["CidrBlock"])

    return ip_ranges


def matches_ip_range(target_ip_range, ip_ranges):
    """Check if passed in ip address is in any of the passed subnets"""
    target_ip_range_obj = ipaddress.ip_network(target_ip_range)
    for range_name in ["org", "default_vpc", "vpc", "aws", "ext"]:
        for ip_addr in ip_ranges[range_name]:
            curr_ip_range_obj = ipaddress.ip_network(ip_addr)
            if target_ip_range_obj.subnet_of(curr_ip_range_obj):
                return {range_name: True}
    return {}


def is_private_ip_range(cidr_ip):
    """Check if passed in cidr ip address is private - follows RFC 1918"""
    ip_addr = cidr_ip.split("/")[0]
    if ip_addr == "0.0.0.0":
        return False
    return ipaddress.ip_address(ip_addr).is_private


def get_per_region_aws_data(args):
    aws_ds = {}

    for region in args["regions"]:
        aws_ds[region] = {}
        sys.stderr.write("STATUS: Checking region - %s - get azs, security groups and network interfaces\n" % region)

        region_ec2 = boto3.client("ec2", region_name=region)

        response = region_ec2.describe_availability_zones()
        aws_ds[region]["azs"] = sorted([x["ZoneName"] for x in response["AvailabilityZones"]])

        response = region_ec2.describe_security_groups()
        aws_ds[region]["security_groups"] = sorted(
            response["SecurityGroups"],
            key=lambda x: x["GroupName"],
        )

        response = region_ec2.describe_network_interfaces()
        aws_ds[region]["network_interfaces"] = response["NetworkInterfaces"]

    return aws_ds


def get_account_id():
    """Get current AWS account id"""
    client = boto3.client("sts")
    return client.get_caller_identity()["Account"]


def dump_aws_data(aws_data, cache_file):
    """Dump AWS into cache"""
    with open(cache_file, "w") as cache_fd:
        cache_fd.write(json.dumps(aws_data, indent=2, default=str))
    return True


def load_aws_data(cache_file):
    """Load AWS from cache"""
    return json.loads(open(cache_file).read())


def scan_sec_groups(aws_data, derived_ip_ranges):
    """Generate security group ds"""
    sec_group_ds = []

    for region in aws_data.keys():
        if "security_groups" not in aws_data[region] or "network_interfaces" not in aws_data[region]:
            continue

        sec_group_to_net_ifaces = map_sec_groups_to_net_ifaces(
            aws_data[region]["security_groups"], aws_data[region]["network_interfaces"]
        )

        for sec_group in aws_data[region]["security_groups"]:

            for ip_perms in sec_group["IpPermissions"]:
                sources = []

                if ip_perms["IpRanges"]:
                    for ip_range_ds in ip_perms["IpRanges"]:
                        data = {
                            "type": "ip_address",
                            "value": ip_range_ds["CidrIp"],
                            "security_approved": False,
                            "is_32_addr": False,
                        }
                        ip_range = ip_range_ds["CidrIp"]

                        data["is_32_addr"] = False
                        if "/32" in ip_range:
                            data["is_32_addr"] = True

                        ip_addr, subnet_mask = ip_range.split("/")
                        if ip_addr == "0.0.0.0":
                            data["ip_range_status"] = "public-0.0.0.0"
                            sources.append(data)
                            continue

                        data["is_private_ip_range"] = is_private_ip_range(ip_range)

                        ip_type = "public"
                        if data["is_private_ip_range"]:
                            ip_type = "private"

                        matches_derived_ip_ranges = matches_ip_range(ip_range, derived_ip_ranges)
                        if matches_derived_ip_ranges:
                            ip_range_status = ip_type + "-" + list(matches_derived_ip_ranges.keys())[0]
                        else:
                            ip_range_status = ip_type + "-other"

                        data["ip_range_status"] = ip_range_status

                        sources.append(data)

                if ip_perms["UserIdGroupPairs"]:
                    for ip_perm in ip_perms["UserIdGroupPairs"]:
                        sources.append({"type": "security_group", "value": ip_perm["GroupId"]})

                sec_group_associations = []
                sec_group_id = sec_group["GroupId"]
                if sec_group_id in sec_group_to_net_ifaces:
                    for net_iface_id in sec_group_to_net_ifaces[sec_group_id]:
                        sec_group_associations.extend(sec_group_to_net_ifaces[sec_group_id][net_iface_id])

                association_count = {}
                for association in sec_group_associations:
                    if association not in association_count:
                        association_count[association] = 1
                    else:
                        association_count[association] += 1

                association_count_str = ""

                for association, count in sorted(association_count.items()):
                    association_count_str += association + ":" + str(count)
                    association_count_str += "|"

                for source in sources:
                    sec_group_ds.append(
                        {
                            "Region": region,
                            "VpcId": sec_group["VpcId"],
                            "GroupId": sec_group["GroupId"],
                            "GroupName": sec_group["GroupName"],
                            "GroupAssociationsCount": len(sec_group_associations),
                            "RuleIpProtocol": ip_perms["IpProtocol"],
                            "RuleSourceType": source["type"],
                            "RuleSource": source["value"],
                            "RuleIpRangeStatus": source.get("ip_range_status", "NA"),
                            "RuleIp32Address": source.get("is_32_addr", "NA"),
                            "RuleFromPort": ip_perms.get("FromPort", "All"),
                            "RuleToPort": ip_perms.get("ToPort", "All"),
                            "GroupDescription": sec_group["Description"],
                            "GroupAssociations": association_count_str,
                        }
                    )

    return sec_group_ds


def map_sec_groups_to_net_ifaces(sec_groups, net_ifaces):
    """Map security groups to network interfaces to find security group associations"""
    sec_group_to_net_ifaces = {}

    for net_iface in net_ifaces:
        if len(net_iface["Groups"]) == 0:
            continue

        for net_sec_group_ds in net_iface["Groups"]:
            sec_group = net_sec_group_ds["GroupId"]
            net_iface_id = net_iface["NetworkInterfaceId"]

            if sec_group not in sec_group_to_net_ifaces:
                sec_group_to_net_ifaces[sec_group] = {}

            if net_iface_id not in sec_group_to_net_ifaces[sec_group]:
                sec_group_to_net_ifaces[sec_group][net_iface_id] = []

            if "Attachment" in net_iface:
                if "InstanceId" in net_iface["Attachment"]:
                    sec_group_to_net_ifaces[sec_group][net_iface_id].append(net_iface["Attachment"]["InstanceId"])
                    continue

            sec_group_to_net_ifaces[sec_group][net_iface_id].append(net_iface["Description"].replace(" ", "_"))

    return sec_group_to_net_ifaces


def get_csv(sec_group_ds):
    """Generate security group csv from ds"""
    output = io.StringIO()
    writer = csv.writer(output)
    headers = [
        "Region",
        "VpcId",
        "GroupId",
        "GroupName",
        "GroupAssociationsCount",
        "RuleIpProtocol",
        "RuleSourceType",
        "RuleSource",
        "RuleIpRangeStatus",
        "RuleIp32Address",
        "RuleFromPort",
        "RuleToPort",
        "GroupDescription",
        "GroupAssociations",
    ]
    writer.writerow(headers)

    for entry in sec_group_ds:
        row = []
        for header in headers:
            row.append(entry[header])
        writer.writerow(row)

    return output.getvalue()


def main():
    args = load_args()
    account_id = get_account_id()

    cache_file_dir = "/tmp/scan_security_groups_cache"
    cache_file = os.path.join(cache_file_dir, account_id + "_aws_sg_data.json")
    if not os.path.exists(cache_file_dir):
        os.makedirs(cache_file_dir)

    aws_data = {}

    if not args["use_cache"]:
        sys.stderr.write("STATUS: Building cache - " + cache_file + "\n")
        aws_data = get_per_region_aws_data(args)
        dump_aws_data(aws_data, cache_file)
    else:
        sys.stderr.write("STATUS: Loading from cache - " + cache_file + "\n")
        aws_data = load_aws_data(cache_file)

    derived_ip_ranges = get_derived_ip_ranges(args)
    sec_group_ds = scan_sec_groups(aws_data, derived_ip_ranges)
    sec_group_csv = get_csv(sec_group_ds)
    print(sec_group_csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
