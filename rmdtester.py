# Copyright 2017-2018 Spirent Communications.

import hashlib
import json
import logging
import os
import resthttp
import socket
import tasks
from conf import settings as S
from collections import defaultdict

_LOGGER = logging.getLogger(__name__)
_CURR_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_PORT = 8888
DEFAULT_SERVER = '127.0.0.1'
DEFAULT_VERSION = 'v1'


class IrmdHttp(object):
    """
    Intel RMD ReST API wrapper object
    """

    def __init__(self, server=None, port=None, api_version=None):
        if not port:
            server = DEFAULT_SERVER
        if not port:
            port = DEFAULT_PORT
        if not api_version:
            api_version = DEFAULT_VERSION
        url = resthttp.RestHttp.url('http', server, port, api_version)
        rest = resthttp.RestHttp(url, None, None, False, True)
        try:
            rest.get_request('workloads')
        except (socket.error, resthttp.ConnectionError,
                resthttp.RestHttpError):
            raise RuntimeError('Cannot connect to RMD server: %s:%s' %
                               (server, port))
        self._rest = rest
        self.workloadids = []
        self._logger = logging.getLogger(__name__)

    def setup_cacheways(self, affinity_map):
        """
        Sets up the cacheways using RMD apis.
        """
        for cos_cat in affinity_map:
            if S.getValue('POLICY_TYPE') == 'COS':
                params = {'core_ids': affinity_map[cos_cat],
                          'policy': S.getValue(cos_cat + '_COS')}
            else:
                minmax = S.getValue(cos_cat + '_CA')
                if len(minmax) < 2:
                    return
                params = {'core_ids': affinity_map[cos_cat],
                          'min_cache': minmax[0],
                          'max_cache': minmax[1]}
            try:
                _, data = self._rest.post_request('workloads', None,
                                                  params)
                if 'id' in data:
                    wl_id = data['id']
                    self.workloadids.append(wl_id)

            except resthttp.RestHttpError as exp:
                if str(exp).find('already exists') >= 0:
                    raise RuntimeError("The cacheway already exist")
                else:
                    raise RuntimeError('Failed to connect: ' + str(exp))

    def reset_all_cacheways(self):
        """
        Resets the cacheways
        """
        try:
            for wl_id in self.workloadids:
                self._rest.delete_request('workloads', str(wl_id))
        except resthttp.RestHttpError as ecp:
            raise RuntimeError('Failed to connect: ' + str(ecp))

    def log_allocations(self):
        """
        Log the current cacheway settings.
        """
        try:
            _, data = self._rest.get_request('workloads')
            self._logger.info("Current Allocations: %s",
                              json.dumps(data, indent=4, sort_keys=True))
        except resthttp.RestHttpError as ecp:
            raise RuntimeError('Failed to connect: ' + str(ecp))


class CacheAllocator(object):
    """
    This class exposes APIs for VSPERF to perform
    Cache-allocation management operations.
    """

    def __init__(self):
        port = S.getValue('RMD_PORT')
        api_version = S.getValue('RMD_API_VERSION')
        server_ip = S.getValue('RMD_SERVER_IP')
        self.irmd_manager = IrmdHttp(str(server_ip), str(port),
                                     str(api_version))

    def setup_llc_allocation(self):
        """
        Wrapper for settingup cacheways
        """
        cpumap = defaultdict(list)
        for i in range(int(S.getValue('WL_VM_COUNT')) +
                       int(S.getValue('WL_PROCESS_COUNT'))):
            cpumap['WL' + str(i)] = S.getValue['WL_CORE_BINDING'][i]
        self.irmd_manager.setup_cacheways(cpumap)

    def cleanup_llc_allocation(self):
        """
        Wrapper for cacheway cleanup
        """
        self.irmd_manager.reset_all_cacheways()

    def log_allocations(self):
        """
        Wrapper for logging cacheway allocations
        """
        self.irmd_manager.log_allocations()


def mac_hash(s):
    """
    return a valid virtual MAC addr
    """
    m = hashlib.md5()
    m.update(s.encode('utf-8'))
    m = m.hexdigest()[0:8]
    return "52:54:%s%s:%s%s:%s%s:%s%s" % tuple(m)


class QemuVM(tasks.Process):
    """
    Class for controling an instance of QEMU
    """
    def __init__(self, index):
        self._running = False
        self._logger = logging.getLogger(__name__)
        self._number = index
        pnumber = int(S.getValue('BASE_VNC_PORT')) + self._number
        cpumask = ",".join(S.getValue('WL_CORE_BINDING')[self._number])
        self._monitor = '%s/vm%dmonitor' % ('/tmp', pnumber)
        name = 'WL%d' % index
        vnc = ':%d' % pnumber
        self._shared_dir = '%s/qemu%d_share' % ('/tmp', pnumber)
        if not os.path.exists(self._shared_dir):
            try:
                os.makedirs(self._shared_dir)
            except OSError as exp:
                raise OSError("Failed to create shared directory %s: %s" %
                              self._shared_dir, exp)

        self.nics_nr = S.getValue('WL_NICS_NR')
        self.image = S.getValue('WL_IMAGE')[self._number]
        self._cmd = ['sudo', '-E', 'taskset', '-c', cpumask,
                     S.getValue('QEMU_CMD'),
                     '-m', S.getValue('WL_MEMORY'),
                     '-smp', S.getValue('WL_SMP'),
                     '-cpu', 'host,migratable=off',
                     '-drive', 'if={},file='.format(
                         S.getValue('BOOT_DRIVE_TYPE')) +
                     self.image, '-boot',
                     'c', '--enable-kvm',
                     '-monitor', 'unix:%s,server,nowait' % self._monitor,
                     '-numa', 'node,memdev=mem -mem-prealloc',
                     '-nographic', '-vnc', str(vnc), '-name', name,
                     '-snapshot', '-net none', '-no-reboot',
                     '-drive',
                     'if=%s,format=raw,file=fat:rw:%s,snapshot=off' %
                     (S.getValue('SHARED_DRIVE_TYPE'),
                      self._shared_dir)
                     ]
        # self.gen_virtio_dev()

    def gen_virtio_dev(self):
        """
        generate `-netdev` and `-device` args for qemu
        @param {string} s - a string to hash
        @param {number} id
        """
        for id in range(int(self.nics_nr)):
            mac = mac_hash(self.image + str(id))
            self._cmd += ['-netdev', 'type=tap,id=hostnet' + str(id) +
                          ',script=no,downscript=no,vhost=on',
                          '-device',
                          'virtio-net-pci,netdev=hostnet' +
                          str(id) + ',mac=' + mac +
                          ',csum=off,gso=off,' +
                          'guest_tso4=off,guest_tso6=off,guest_ecn=off']

    def start(self):
        """
        Start QEMU instance
        """
        super(QemuVM, self).start()
        self._running = True

    def stop(self):
        """
        Stops VNF instance.
        """
        if self.is_running():
            self._logger.info('Killing WL...')
            # force termination of VNF and wait to terminate; It will avoid
            # sporadic reboot of host.
            super(QemuVM, self).kill(signal='-9', sleep=10)
        # remove shared dir if it exists to avoid issues with file consistency
        if os.path.exists(self._shared_dir):
            tasks.run_task(['rm', '-f', '-r', self._shared_dir], self._logger,
                           'Removing content of shared directory...', True)
        self._running = False

    def print_cmd(self):
        print(self._cmd)


class StressorVM(object):
    def __init__(self):
        self.qvm_list = []
        for vmindex in range(int(S.getValue('WL_VM_COUNT'))):
            qvm = QemuVM(vmindex)
            self.qvm_list.append(qvm)

    def start(self, index):
        # for vm in self.qvm_list:
        vm = self.qvm_list[index]
        vm.start()

    def stop(self, index):
        # for vm in self.qvm_list:
        vm = self.qvm_list[index]
        vm.stop()

    def print_command(self, index):
        # for vm in self.qvm_list:
        vm = self.qvm_list[index]
        vm.print_cmd()


def main():
    # configure settings
    S.load_from_dir(_CURR_DIR)
    vmcontrol = StressorVM()
    cachecontrol = CacheAllocator()
    input("Press Enter to start workload-1")
    vmcontrol.start(0)
    input("Press Enter to perform cache allocation")
    cachecontrol.setup_llc_allocation()
    input("Press Enter to start workload-2")
    vmcontrol.start(1)
    input("Press Enter to stop workload-2")
    vmcontrol.stop(0)
    input("Press Enter to stop workload-1")
    vmcontrol.stop(1)
    input("Press Enter to cleanup allocations")
    cachecontrol.cleanup_llc_allocation()
    print("RMD-Testing is done, Goodbye!")


if __name__ == "__main__":
    main()
