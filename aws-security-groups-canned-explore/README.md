Reference code for substack post - WIP

### Pre-requisites

Install the following:

1. [q](http://harelba.github.io/q/).
2. [csv2table](https://github.com/saurabh-hirani/bin/blob/master/csv2table)
3. Install the modules present in [./requirements.txt](./requirements.txt)

### Sample usage

  ```
  python scan_security_groups.py --region ap-south-1 --org-ip-addr-file ./ip-addrs/org.json > /tmp/output.csv
  ```

  where `./ip-addrs/org.json` lists allowed organization public IPs. Change the json file or remove the `--org-ip-add-file` as per your need.

- Find all security groups

  ```
  q -H -d ',' -O "select Region as region, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                  RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                  from /tmp/output.csv" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```


- Above + only security groups with ip\_address rules (i.e. ignore security groups which reference other security groups in sources)

  ```
  q -H -d ',' -O "select Region as region, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                  RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                  from /tmp/output.csv where RuleSourceType == 'ip_address'" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```

- Above + association count > 0

  ```
  q -H -d ',' -O "select Region as region, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                  RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                  from /tmp/output.csv where RuleSourceType == 'ip_address' and
                  GroupAssociationsCount > 0" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```


- Above + non-standard IP + non-80,443

  ```
  q -H -d ',' -O "select Region as region, VpcId as vpc, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                    RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                    from /tmp/output.csv where RuleSourceType == 'ip_address' and
                    GroupAssociationsCount > 0 and
                    RuleFromPort not in (80, 443) and
                    RuleIpRangeStatus in ('public-other')" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```

  where `RuleIpRangeStatus in ('public-other')` catches rules from unknown public IPs i.e. IPs which do not fall in these categories:

  - public-org - IP Addresses present in [./ip-addrs/org.json](./ip-addrs/org.json)
  - private-vpc - IP addresses from private and non-default VPCs.
  - private-default_vpc - Same as above but.
  - public-aws - AWS public IPs.
  - public-0.0.0.0 - open the world.

  Remember that time when you added a security group rule for port 22 for your ISP's public IP but forgot to delete it? This catches that.

- Security groups associated with port 22.

  ```
  q -H -d ',' -O "select Region as region, VpcId as vpc, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                    RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                    from /tmp/output.csv where RuleSourceType == 'ip_address' and
                    RuleFromPort in (22)" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```

- Security groups associated with port 22 and open to the world.

  ```
  q -H -d ',' -O "select Region as region, VpcId as vpc, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                    RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                    from /tmp/output.csv where RuleSourceType == 'ip_address' and
                    RuleFromPort in (22) and RuleIpRangeStatus in ('public-0.0.0.0')" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```

- Security groups associated with ports other than port 80, 443, 22.


  ```
  q -H -d ',' -O "select Region as region, VpcId as vpc, GroupId as id, GroupName as name, GroupAssociationsCount as grpcount,
                    RuleSource as src, RuleFromPort as from_port, RuleToPort as to_port, RuleIpRangeStatus as status
                    from /tmp/output.csv where RuleSourceType == 'ip_address' and
                    RuleFromPort not in (80, 443, 22)" | ROW_TEXTWRAP_LEN=50 TABLE_HAS_HEADER=1 csv2table
  ```
