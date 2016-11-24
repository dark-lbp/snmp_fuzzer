#!/usr/bin/env python
# coding:utf-8
from scapy.all import *

from Base import BaseTarget
# loading mibs
load_mib("mibs/*")

snmp_error_id = [2, 3, 5, 6, 17, 10, 12, 14]

ASN1_Type = {
    0: [scapy.asn1.asn1.ASN1_IPADDRESS, RandIP()],
    1: [scapy.asn1.asn1.ASN1_STRING, RandBin()],
    2: [scapy.asn1.asn1.ASN1_INTEGER, RandInt()],
    3: [scapy.asn1.asn1.ASN1_GAUGE32, RandInt()]
}

SNMP_Error_code = {
    0: [0, 'noError (0)'],
    1: [1, 'tooBig (1)'],
    2: [2, 'noSuchName (2)'],
    3: [3, 'badValue (3)'],
    4: [4, 'readOnly (4)'],
    5: [5, 'genErr (5)'],
    6: [6, 'noAccess (6)'],
    7: [7, 'wrongType (7)'],
    8: [8, 'wrongLength (8)'],
    9: [9, 'wrongEncoding (9)'],
    10: [10, 'wrongValue (10)'],
    11: [11, 'noCreation (11)'],
    12: [12, 'inconsistentValue (12)'],
    13: [13, 'resourceUnavailable (13)'],
    14: [14, 'commitFailed (14)'],
    15: [15, 'undoFailed (15)'],
    16: [16, 'authorizationError (16)'],
    17: [17, 'notWritable (17)'],
    18: [18, 'inconsistentName (18)']
}


class SnmpTarget(BaseTarget):

    def __init__(self, name, target, monitor_port=None, community='private', version=2, oid='.1', output_path='./output', fuzz_count=100, timeout=1, nic=None, logger=None):
        '''
        :param name: Name of target
        :param target: IP address of target
        :param monitor_port: Tcp port used to check target alive
        :param community: Snmp community with write privilege, default:'private'
        :param version: Snmp version only support version 1 and 2
        :param oid: Snmp scan start oid, default: '.1'
        :param output_path: Path to store scan result
        :param fuzz_count: Fuzz count of each writable oid
        :param timeout: Timeout for connect
        :param nic: Network interface name which used to connect to target
        :param logger: Logger of this target
        '''
        super(SnmpTarget, self).__init__(name, logger)
        self._target = target
        self._monitor_port = monitor_port
        self._community = community
        self._oid = oid
        self._nic = nic
        self._timeout = timeout
        self.oid_list = []
        self.oid_write_list = []
        self.set_packets = []
        self._test_cases = []
        self._sent_packets = []
        self._crash_packets = []
        self._fuzz_count = fuzz_count
        self._output_path = output_path
        self._sent_packets_file_count = 0
        if version == 1:
            self._version = 'v1'
        elif version == 2:
            self._version = 'v2c'
        if not os.path.exists(self._output_path):
            os.mkdir(self._output_path)
        self._oid_list_file = open("%s/%s_oid_list_file.txt" %
                                   (self._output_path, self._target), 'w')
        self._oid_writeable_list_file = open(
            "%s/%s_oid_writeable_list_file.txt" %
            (self._output_path, self._target), 'w')
        self._snmp_set_packets_file = "%s/%s_snmp_set_packet_list.pcap" % (
            self._output_path, self._target)
        self._snmp_crash_packets_file = "%s/%s_snmp_crash_packets.pcap" % (
            self._output_path, self._target)
        self._snmp_sent_packets_file = "%s/%s_snmp_sent_packets_%s.pcap" % (
            self._output_path, self._target,
            str(self._sent_packets_file_count))

    def _create_get_request(self, my_oid):
        get_payload = IP(dst=self._target) / UDP(sport=161, dport=161) / SNMP(
            version=self._version,
            community=self._community,
            PDU=SNMPnext(
                varbindlist=[SNMPvarbind(
                    oid=ASN1_OID(my_oid), value='')]))
        return get_payload

    def _create_set_request(self, varbindlist):
        set_payload = IP(dst=self._target) / UDP(sport=161, dport=161) / SNMP(
            version=self._version,
            community=self._community,
            PDU=SNMPset(varbindlist=[varbindlist]))
        return set_payload

    def _create_get_request_by_packet(self, packet):
        my_oid = packet[SNMP].PDU[SNMPvarbind].oid
        get_payload = copy.deepcopy(packet)
        get_payload[SNMP].PDU = SNMPget(
            varbindlist=[SNMPvarbind(
                oid=my_oid, value='')])
        # fix the packet
        del (get_payload[IP].chksum)
        del (get_payload[IP].len)
        del (get_payload[UDP].chksum)
        del (get_payload[UDP].len)
        del (get_payload.len)
        return get_payload

    def _create_get_next_request_by_packet(self, packet):
        my_oid = packet[SNMP].PDU[SNMPvarbind].oid
        get_next_payload = copy.deepcopy(packet)
        get_next_payload[SNMP].PDU = SNMPnext(
            varbindlist=[SNMPvarbind(
                oid=my_oid, value='')])
        # fix the packet
        del (get_next_payload[IP].chksum)
        del (get_next_payload[IP].len)
        del (get_next_payload[UDP].chksum)
        del (get_next_payload[UDP].len)
        del (get_next_payload.len)
        return get_next_payload

    def _create_fuzz_packet(self, packet):
        my_valtype = packet[SNMP].PDU[SNMPvarbind].value
        if isinstance(my_valtype, ASN1_Type[2][0]):
            packet[SNMP].PDU[SNMPvarbind].value.val = self._get_asn_value_type(
                my_valtype)
        else:
            packet[SNMP].PDU[SNMPvarbind].value.val = str(
                self._get_asn_value_type(my_valtype))
        # fix the packet
        del (packet[IP].chksum)
        del (packet[IP].len)
        del (packet[UDP].chksum)
        del (packet[UDP].len)
        del (packet.len)
        return packet

    def oid_scan(self):
        while True:
            get_payload = self._create_get_request(self._oid)
            get_rsp_payload = sr1(get_payload,
                                  timeout=self._timeout,
                                  verbose=0,
                                  iface=self._nic)
            if get_rsp_payload:
                self.logger.debug(str(get_rsp_payload).encode('hex'))
                self.logger.debug(get_rsp_payload.show(dump=True))
            try:
                if self._oid == get_rsp_payload[SNMP].PDU[SNMPvarbind].oid.val:
                    self.logger.info('End of MIB')
                    break
            except Exception as e:
                self.logger.error(e)
                pass
            else:
                self._oid = get_rsp_payload[SNMP].PDU[SNMPvarbind].oid.val
                self.logger.info('Found oid :%s' % self._oid)
                oid_display = conf.mib._oidname(self._oid)
                value_type = get_rsp_payload[SNMP].PDU[SNMPvarbind].value
                value = get_rsp_payload[SNMP].PDU[SNMPvarbind].value.val
                varbindlist = get_rsp_payload[SNMP].PDU[SNMPvarbind]
                set_payload = self._create_set_request(varbindlist)
                try:
                    set_rsp = sr1(set_payload,
                                  timeout=self._timeout,
                                  verbose=0,
                                  iface=self._nic)
                    if set_rsp[SNMP].PDU.error.val not in snmp_error_id:
                        self.logger.info("%s is writeable" % self._oid)
                        self.oid_write_list.append(
                            (oid_display, self._oid, type(value_type), value))
                        self.set_packets.append(set_payload)
                except:
                    self.logger.error('Time Out')
                self.oid_list.append(
                    (oid_display, self._oid, type(value_type), value))
                time.sleep(0.3)

    def set_test_case_range(self, test_case_range=None):
        if test_case_range is None:
            self._test_cases = range(len(self.set_packets))
        else:
            p_single = re.compile(r'(\d+)$')
            p_open_left = re.compile(r'-(\d+)$')
            p_open_right = re.compile(r'(\d+)-$')
            p_closed = re.compile(r'(\d+)-(\d+)$')
            open_left_found = False
            open_right_found = False
            open_end_start = None
            for entry in test_case_range.split(','):
                entry = entry.strip()

                # single number
                match = p_single.match(entry)
                if match:
                    self._test_cases.append(int(match.groups()[0]))
                    # self._list.append(int(match.groups()[0]))
                    continue

                # open left
                match = p_open_left.match(entry)
                if match:
                    if open_left_found:
                        raise Exception(
                            'You have two test ranges that start from zero')
                    open_left_found = True
                    end = int(match.groups()[0])
                    self._test_cases.extend(list(range(0, end + 1)))
                    # self._list.extend(list(range(0, end + 1)))
                    continue

                # open right
                match = p_open_right.match(entry)
                if match:
                    if open_right_found:
                        raise Exception(
                            'You have two test ranges that does not end')
                    open_right_found = True
                    open_end_start = int(match.groups()[0])
                    continue

                # closed range
                match = p_closed.match(entry)
                if match:
                    start = int(match.groups()[0])
                    end = int(match.groups()[1])
                    self._test_cases.extend(list(range(start, end + 1)))
                    continue

                # invalid expression
                raise Exception('Invalid range found: %s' % entry)
            as_set = set(self._test_cases)
            if len(as_set) < len(self._test_cases):
                raise Exception('Overlapping ranges in range list')
            self._test_cases = sorted(list(as_set))
            if open_end_start and len(self._test_cases) and self._test_cases[
                    -1] >= open_end_start:
                raise Exception('Overlapping ranges in range list')
            pass

    def save_scan_result(self):
        for i in range(len(self.oid_list)):
            self._oid_list_file.write(str(self.oid_list[i]))
            self._oid_list_file.write('\r')

        for i in range(len(self.oid_write_list)):
            self._oid_writeable_list_file.write(str(self.oid_write_list[i]))
            self._oid_writeable_list_file.write('\r')

        wrpcap(self._snmp_set_packets_file, self.set_packets)

    def save_fuzz_result(self):
        wrpcap(self._snmp_sent_packets_file, self._sent_packets)
        wrpcap(self._snmp_crash_packets_file, self._crash_packets)

    def _save_sent_packet(self, packet):
        self._sent_packets.append(packet)
        if len(self._sent_packets) >= 200:
            wrpcap(self._snmp_sent_packets_file, self._sent_packets)
            self._sent_packets = []
            self._sent_packets_file_count += 1
            self._snmp_sent_packets_file = "%s/%s_snmp_sent_packets_%s.pcap" % (
                self._output_path, self._target,
                str(self._sent_packets_file_count))

    def read_test_case_from_pcap(self, pcap_file):
        self.set_packets = rdpcap(pcap_file)

    def _get_asn_value_type(self, value_type):
        for i in range(len(ASN1_Type)):
            if isinstance(value_type, ASN1_Type[i][0]) is True:
                return ASN1_Type[i][1]

    def _get_errror_code(self, code):
        for i in range(len(SNMP_Error_code)):
            if SNMP_Error_code[i][0] == code:
                return SNMP_Error_code[i][1]
        self.logger.error('Unknown Error Code: %s' % code)

    def _is_target_alive(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((self._target, self._monitor_port))
            s.close()
        except:
            return False
        return True

    def fuzz(self):
        if not self._test_cases:
            self.set_test_case_range()
        for test_case in self._test_cases:
            try:
                for i in range(self._fuzz_count):
                    # send set packet
                    set_payload = copy.deepcopy(self.set_packets[test_case])
                    set_payload = self._create_fuzz_packet(set_payload)
                    self.logger.info("Running test case No.%s %s/%s" %
                                     (test_case, i, self._fuzz_count))
                    self._save_sent_packet(set_payload)
                    set_rsp = sr1(set_payload,
                                  timeout=self._timeout,
                                  verbose=0,
                                  iface=self._nic)
                    if set_rsp is None:
                        self.logger.warning(
                            "Target not response with snmp set packet in packet NO.%s,TestCase No.%s"
                            % (i, test_case))
                        if self._is_target_alive():
                            self.logger.info("Target is still alive!")
                        else:
                            self.logger.error(
                                "Can't Connect to Target at TCP Port: %s" %
                                self._monitor_port)
                            self._crash_packets.append(set_payload)
                            return
                    else:
                        self._save_sent_packet(set_rsp)
                        if set_rsp[SNMP].PDU.error.val != 0:
                            self.logger.warning(
                                "Set failed with error code: %s in packet NO.%s,TestCase No.%s"
                                % (self._get_errror_code(set_rsp[
                                    SNMP].PDU.error.val), i, test_case))
                    # send get packet
                    get_payload = copy.deepcopy(self.set_packets[test_case])
                    get_payload = self._create_get_request_by_packet(
                        get_payload)
                    self._save_sent_packet(get_payload)
                    get_rsp = sr1(get_payload,
                                  timeout=self._timeout,
                                  verbose=0,
                                  iface=self._nic)
                    if get_rsp is None:
                        self.logger.warning(
                            "Target not response with snmp get packet in packet NO.%s,TestCase No.%s"
                            % (i, test_case))
                        if self._is_target_alive():
                            self.logger.info("Target is still alive!")
                        else:
                            self.logger.error(
                                "Can't Connect to Target at TCP Port: %s" %
                                self._monitor_port)
                            self._crash_packets.append(set_payload)
                            return
                    else:
                        self._save_sent_packet(get_rsp)
                        if get_rsp[SNMP].PDU.error.val != 0:
                            self.logger.info(
                                "Get failed with error code %s in packet NO.%s,TestCase No.%s"
                                % (self._get_errror_code(get_rsp[
                                    SNMP].PDU.error.val), i, test_case))
                    # send get_next packet
                    get_next_payload = copy.deepcopy(self.set_packets[
                        test_case])
                    get_next_payload = self._create_get_next_request_by_packet(
                        get_next_payload)
                    self._save_sent_packet(get_next_payload)
                    get_next_rsp = sr1(get_next_payload,
                                       timeout=self._timeout,
                                       verbose=0,
                                       iface=self._nic)
                    if get_next_rsp is None:
                        self.logger.warning(
                            "Target not response with snmp get_next packet in packet NO.%s,TestCase No.%s"
                            % (i, test_case))
                        if self._is_target_alive():
                            self.logger.info("Target is still alive!")
                        else:
                            self.logger.error(
                                "Can't Connect to Target at TCP Port: %s" %
                                self._monitor_port)
                            self._crash_packets.append(set_payload)
                            return
                    else:
                        self._save_sent_packet(get_next_rsp)
                        if get_next_rsp[SNMP].PDU.error.val != 0:
                            self.logger.info(
                                "Get_next failed with error code %s in packet NO.%s,TestCase No.%s"
                                % (self._get_errror_code(get_next_rsp[
                                    SNMP].PDU.error.val), i, test_case))
            except KeyboardInterrupt:
                self.save_fuzz_result()
                time.sleep(1)
                return

            except:
                self.save_fuzz_result()
                self.logger.error("Unexpected error: %s" % sys.exc_info()[0])
                return
