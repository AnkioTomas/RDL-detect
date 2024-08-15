#!/usr/bin/env python
# coding=utf-8
"""
基于https://github.com/fortra/impacket/blob/master/examples/rpcdump.py
应对CVE-2024-38077漏洞，通过RPC协议快速排查RDL服务开放情况

Author: MurphySec 2024.08.09
Thanks:
   Javier Kohen
   Alberto Solino (@agsolino)
"""

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse

from impacket.http import AUTH_NTLM
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import uuid, version
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpch import RPC_PROXY_INVALID_RPC_PORT_ERR, \
    RPC_PROXY_CONN_A1_0X6BA_ERR, RPC_PROXY_CONN_A1_404_ERR, \
    RPC_PROXY_RPC_OUT_DATA_404_ERR

class RPCDump:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s[135]'},
        139: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        443: {'bindstr': r'ncacn_http:[593,RpcProxy=%s:443]'},
        445: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        593: {'bindstr': r'ncacn_http:%s'}
    }

    def __init__(self, username='', password='', domain='', hashes=None, port=135):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__port = port
        self.__stringbinding = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):
        """Dumps the list of endpoints registered with the mapper
        listening at addr. remoteName is a valid host name or IP
        address in string format.
        """
        entries = []

        self.__stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        logging.debug('StringBinding %s' % self.__stringbinding)
        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)

        if self.__port in [139, 445]:
            # Setting credentials for SMB
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)

            # Setting remote host and port for SMB
            rpctransport.setRemoteHost(remoteHost)
            rpctransport.set_dport(self.__port)
        elif self.__port in [443]:
            # Setting credentials only for RPC Proxy, but not for the MSRPC level
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)

            rpctransport.set_auth_type(AUTH_NTLM)
        else:
            pass

        try:
            entries = self.__fetchList(rpctransport)
        except Exception as e:
            error_text = 'Protocol failed: %s' % e
            logging.critical(error_text)

            if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text or \
               RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or \
               RPC_PROXY_CONN_A1_404_ERR in error_text or \
               RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
                logging.critical("This usually means the target does not allow "
                                 "to connect to its epmapper using RpcProxy.")
                return

        endpoints = {}
        for entry in entries:
            binding = epm.PrintStringBinding(entry['tower']['Floors'])
            tmpUUID = str(entry['tower']['Floors'][0])
            if tmpUUID not in endpoints:
                endpoints[tmpUUID] = {'Bindings': []}
            if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
            else:
                endpoints[tmpUUID]['EXE'] = 'N/A'
            endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
            endpoints[tmpUUID]['Bindings'].append(binding)

            if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
                endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
            else:
                endpoints[tmpUUID]['Protocol'] = "N/A"

        found = False
      # ANSI escape sequences for colors
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        RESET = '\033[0m'

        for endpoint in list(endpoints.keys()):
            if '3d267954-eeb7-11d1-b94e-00c04fa3080d' in endpoint.lower():
                logging.info(GREEN + ' %s Found Terminal Server Licensing ' % remoteName + RESET)
                logging.debug(YELLOW + '服务信息：' + RESET)
                logging.debug(GREEN + "Protocol: %s " % endpoints[endpoint]['Protocol'] + RESET)
                logging.debug(GREEN + "Provider: %s " % endpoints[endpoint]['EXE'] + RESET)
                logging.debug(GREEN + "UUID    : %s %s" % (endpoint, endpoints[endpoint]['annotation']) + RESET)
                logging.debug(GREEN + "Bindings: " + RESET)
                found = True
                for binding in endpoints[endpoint]['Bindings']:
                    logging.debug(CYAN + "          %s" % binding + RESET)
                break

        if not entries:
            logging.critical(YELLOW + ' %s RPC Check Error ' % remoteName + RESET)

        if entries and not found:
            logging.critical(RED + ' %s Not Found Terminal Server Licensing' % remoteName + RESET)


    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        dce.connect()

        resp = epm.hept_lookup(None, dce=dce)

        dce.disconnect()

        return resp

# Process command-line arguments.
if __name__ == '__main__':
    logger.init()

    parser = argparse.ArgumentParser(add_help=True, description="基于RPC dump排查RDL服务开放情况")
    parser.add_argument('-f', '--file', required=True, help='包含目标IP的文件，每行一个IP地址或主机名')
    parser.add_argument('-debug', action='store_true', help='调试模式')

    parser.add_argument('-port', choices=['135', '139', '443', '445', '593'], nargs='?', default='135', metavar="destination port",
                       help='需要探测的端口，默认为135')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    with open(options.file, 'r') as file:
        targets = file.read().splitlines()

    for target in targets:

        dumper = RPCDump('', '', target, ':', int(options.port))

        dumper.dump(target, target)
