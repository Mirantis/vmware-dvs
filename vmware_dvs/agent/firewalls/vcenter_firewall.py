# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from multiprocessing import Process, Queue
import signal
import threading
import time

from neutron.agent import firewall
from neutron.i18n import _LI
from oslo_log import log as logging
from oslo_vmware import exceptions as vmware_exceptions

from vmware_dvs.common import config
from vmware_dvs.common import exceptions
from vmware_dvs.utils import security_group_utils as sg_util
from vmware_dvs.utils import dvs_util


LOG = logging.getLogger(__name__)

CONF = config.CONF
CLEANUP_REMOVE_TASKS_TIMEDELTA = 60


def firewall_main(list_queues, remove_queue):
    dvs_firewall = DVSFirewallUpdater(list_queues, remove_queue)
    signal.signal(signal.SIGTERM, dvs_firewall._handle_sigterm)
    dvs_firewall.updater_loop()


class DVSFirewallUpdater(object):

    def __init__(self, list_queues, remove_queue):
        self.pq = PortQueue(list_queues, remove_queue)
        self.run_daemon_loop = True
        self.pq.port_updater_loop()

    def updater_loop(self):
        while self.run_daemon_loop:
            try:
                r_ports = self.pq.get_remove_tasks()
                if r_ports:
                    remover(self.pq, r_ports)

                dvs, ports = self.pq.get_update_tasks()
                if dvs and ports > 0:
                    updater(dvs, ports)
                else:
                    time.sleep(1)
            except (vmware_exceptions.VMwareDriverException,
                    exceptions.VMWareDVSException):
                pass

    def _handle_sigterm(self, signum, frame):
        LOG.info(_LI("Termination of firewall process called"))
        self.run_daemon_loop = False


class PortQueue(object):
    def __init__(self, list_queues, remove_queue):
        self.list_queues = list_queues
        self.remove_queue = remove_queue
        self.removed = {}
        self.update_store = {}
        self.remove_store = []
        self.network_dvs_map = {}
        self.networking_map = dvs_util.create_network_map_from_config(
            CONF.ML2_VMWARE)

    # Todo: add roundrobin for active DVS. SlOPS
    def get_update_tasks(self, number=5):
        for dvs, tasks in self.update_store.iteritems():
            if tasks:
                ret = tasks[:number]
                self.update_store[dvs] = tasks[number:]
                return dvs, ret
        return None, []

    def get_remove_tasks(self):
        ret = self.remove_store
        self.remove_store = []
        return ret

    def _get_update_tasks(self):
        for queue in self.list_queues:
            while not queue.empty():
                request = queue.get()
                for port in request:
                    dvs = self.get_dvs(port)
                    if dvs:
                        stored_tasks = self.update_store.get(dvs, [])
                        index = next((i for i, p in enumerate(stored_tasks)
                                      if p['id'] == port['id']), None)
                        if index is not None:
                            stored_tasks[index] = port
                        else:
                            stored_tasks.append(port)
                        self.update_store[dvs] = stored_tasks

    def _get_remove_tasks(self):
        while not self.remove_queue.empty():
            port = self.remove_queue.get()
            self.removed[port['id']] = time.time()
            self.remove_store.append(port)

    def _cleanup_removed(self):
        current_time = time.time()
        for port_id, remove_time in self.removed.items():
            if current_time - remove_time > CLEANUP_REMOVE_TASKS_TIMEDELTA:
                del self.removed[port_id]

    def get_dvs(self, port):
        port_network = port['network_id']
        if port_network in self.network_dvs_map:
            dvs = self.network_dvs_map[port_network]
        else:
            dvs = dvs_util.get_dvs_by_network(
                self.networking_map.values(), port_network)
            self.network_dvs_map[port_network] = dvs
        return dvs

    def port_updater_loop(self):
        self._get_update_tasks()
        self._get_remove_tasks()
        for dvs in self.update_store:
            self.update_store[dvs] = [item for item in self.update_store[dvs]
                                      if item['id'] not in self.removed]
        self._cleanup_removed()
        threading.Timer(1, self.port_updater_loop).start()


@dvs_util.wrap_retry
def updater(dvs, port_list):
    sg_util.update_port_rules(dvs, port_list)


def remover(pq, ports_list):
    for port in ports_list:
        dvs = pq.get_dvs(port)
        if dvs:
            dvs.release_port(port)


class DVSFirewallDriver(firewall.FirewallDriver):
    """DVS Firewall Driver.
    """
    def __init__(self):
        self.dvs_ports = {}
        self._defer_apply = False
        self.list_queues = []
        for x in xrange(10):
            self.list_queues.append(Queue())
        self.remove_queue = Queue()
        self.fw_process = Process(
            target=firewall_main, args=(self.list_queues, self.remove_queue))
        self.fw_process.start()

    def stop_all(self):
        self.fw_process.terminate()

    def prepare_port_filter(self, ports):
        self._process_port_filter(ports)

    def apply_port_filter(self, ports):
        self._process_port_filter(ports)

    def update_port_filter(self, ports):
        self._process_port_filter(ports)

    def _process_port_filter(self, ports):
        LOG.info(_LI("Set security group rules for ports %s"),
                 [p['id'] for p in ports])
        for port in ports:
            self.dvs_ports[port['device']] = port
        self._apply_sg_rules_for_port(ports)

    def remove_port_filter(self, ports):
        LOG.info(_LI("Remove ports with rules"))
        for p_id in ports:
            port = self.dvs_ports.get(p_id)
            self.remove_queue.put(port)
            self.dvs_ports.pop(port['device'], None)

    @property
    def ports(self):
        return self.dvs_ports

    def _apply_sg_rules_for_port(self, ports):
        for port in ports:
            queue = self._get_free_queue()
            queue.put([{'id': port['id'], 'network_id': port['network_id'],
                'security_group_rules': port['security_group_rules'],
                'binding:vif_details': port['binding:vif_details']}])

    def _get_free_queue(self):
        shortest_queue = self.list_queues[0]
        for queue in self.list_queues:
            queue_size = queue.qsize()
            if queue_size == 0:
                return queue
            if queue_size < shortest_queue.qsize():
                shortest_queue = queue
        return shortest_queue

    def update_security_group_rules(self, sg_id, sg_rules):
        pass

    def security_groups_provider_updated(self):
        LOG.info(_("Ignoring default security_groups_provider_updated RPC."))

    def update_security_group_members(self, sg_id, sg_members):
        pass

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        pass

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass
