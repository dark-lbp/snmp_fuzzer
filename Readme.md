### Snmp fuzz tools Example
#### Scan writeable oid from target
```python
>>> from snmp_set_fuzz import *
>>> target = '192.168.70.50'
>>> port = 80
>>> count = 10
>>> nic = conf.route.route(target)[0]
>>> Target = SnmpTarget(name='test', monitor_port=port, oid='.1.3', version=2, target=target, nic=nic, fuzz_count=count)
>>> Target.oid_scan()
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.1.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.2.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.3.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.4.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.2.1.1.4.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.5.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.2.1.1.5.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.6.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.2.1.1.6.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.1.7.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.1.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.1.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.2.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.3.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.4.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.5.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.6.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.2.1.2.2.1.7.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.2.1.2.2.1.7.0 is writeable
..............
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.4.1.95.2.3.1.1.1.1.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.4.1.95.2.3.1.1.1.2.0
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.4.1.95.2.3.1.1.1.3.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.4.1.95.2.3.1.1.1.3.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.4.1.95.2.3.1.1.1.4.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.4.1.95.2.3.1.1.1.4.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.4.1.95.2.4.1.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.4.1.95.2.4.1.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.4.1.95.2.4.2.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.4.1.95.2.4.2.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] Found oid :1.3.6.1.4.1.95.2.4.3.0
[INFO    ][snmp_set_fuzz.oid_scan] 1.3.6.1.4.1.95.2.4.3.0 is writeable
[INFO    ][snmp_set_fuzz.oid_scan] End of MIB
>>> Target.save_scan_result()
>>> # This cmd will save all result to ./output folder.
```

#### Read test case from pcap file
```python
>>> from snmp_set_fuzz import *
>>> target = '192.168.70.50'
>>> port = 80
>>> count = 10
>>> nic = conf.route.route(target)[0]
>>> Target = SnmpTarget(name='test', monitor_port=port, oid='.1.3', version=2, target=target, nic=nic, fuzz_count=count)
>>> print(Target.set_packets)
>>> []
>>> # This time we didn't scan Target
>>> # This cmd will read all packet from pcap file and save to Target.set_packets
>>> Target.read_test_case_from_pcap('./output/192.168.70.50_snmp_set_packet_list.pcap')  
>>> print(Target.set_packets)
<192.168.70.50_snmp_set_packet_list.pcap: TCP:0 UDP:37 ICMP:0 Other:0>
```

####  Start fuzz target

```python
>>> from snmp_set_fuzz import *
>>> target = '192.168.70.50'
>>> port = 80
>>> count = 10
>>> nic = conf.route.route(target)[0]
>>> Target = SnmpTarget(name='test', monitor_port=port, oid='.1.3', version=2, target=target, nic=nic, fuzz_count=count)
>>> Target.read_test_case_from_pcap('./output/192.168.70.50_snmp_set_packet_list.pcap')
>>> Target.fuzz()
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.0 0/10
[WARNING ][snmp_set_fuzz.fuzz] Target not response with snmp set packet in packet NO.0,TestCase No.0
[INFO    ][snmp_set_fuzz.fuzz] Target is still alive!
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.0 1/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.0 2/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.0 3/10
[WARNING ][snmp_set_fuzz.fuzz] Set failed with error code: wrongLength (8) in packet NO.3,TestCase No.0
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.0 4/10
[WARNING ][snmp_set_fuzz.fuzz] Set failed with error code: wrongLength (8) in packet NO.4,TestCase No.0
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.0 5/10
[WARNING ][snmp_set_fuzz.fuzz] Set failed with error code: wrongLength (8) in packet NO.5,TestCase No.0
........
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 4/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 5/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 6/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 7/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 8/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 9/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.5 0/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.5 1/10
[WARNING ][snmp_set_fuzz.fuzz] Target not response with snmp get packet in packet NO.1,TestCase No.5
[ERROR   ][snmp_set_fuzz.fuzz] Can't Connect to Target at TCP Port: 80
>>> # Target crash
>>> # This cmd will save crash packet and all sent packet to ./output folder
>>> Target.save_fuzz_result()
```

#### Fuzz specific test case
```
>>> from snmp_set_fuzz import *
>>> target = '192.168.70.50'
>>> port = 80
>>> count = 10
>>> nic = conf.route.route(target)[0]
>>> Target = SnmpTarget(name='test', monitor_port=port, oid='.1.3', version=2, target=target, nic=nic, fuzz_count=count)
>>> Target.read_test_case_from_pcap('./output/192.168.70.50_snmp_set_packet_list.pcap')
>>> # Set_test_case_range can set specific test case to fuzz
>>> # If you want only fuzz No.8 test case, you can use this Target.set_test_case_range('8')
>>> # If you want fuzz test case up to No.8, you can use this  Target.set_test_case_range('-8')
>>> # If you want fuzz test case from No.8, you can use this  Target.set_test_case_range('8-')
>>> # If you want fuzz test case from No.8 to No.10, you can use this  Target.set_test_case_range('8-10')
>>> # It's also support combine option, Target.set_test_case_range('-8,10,12,14-15,18-')
>>> Target.set_test_case_range('4-5')
>>> Target.fuzz()
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 0/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 1/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 2/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 3/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 4/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 5/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 6/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 7/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 8/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.4 9/10
[INFO    ][snmp_set_fuzz.fuzz] Running test case No.5 0/10
[WARNING ][snmp_set_fuzz.fuzz] Target not response with snmp get packet in packet NO.0,TestCase No.5
[ERROR   ][snmp_set_fuzz.fuzz] Can't Connect to Target at TCP Port: 80
>>> Target.save_fuzz_result()
```
