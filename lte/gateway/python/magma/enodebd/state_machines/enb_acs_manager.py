"""
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re
import requests
from typing import Any, List, Optional

from magma.common.service import MagmaService
from magma.configuration.service_configs import load_service_config
from magma.enodebd.device_config.configuration_util import is_enb_registered
from magma.enodebd.devices.device_map import get_device_handler_from_name
from magma.enodebd.devices.device_utils import EnodebDeviceName
from magma.enodebd.exceptions import UnrecognizedEnodebError
from magma.enodebd.logger import EnodebdLogger as logger
from magma.enodebd.state_machines.acs_state_utils import (
    get_device_name_from_inform,
)
from magma.enodebd.state_machines.enb_acs import EnodebAcsStateMachine
from magma.enodebd.tr069 import models
from spyne import ComplexModelBase
from spyne.server.wsgi import WsgiMethodContext


class StateMachineManager:
    """
    Delegates tr069 message handling to a dedicated state machine for the
    device.
    """

    def __init__(
        self,
        service: MagmaService,
    ):
        self._ip_serial_mapping = IpToSerialMapping()
        self._service = service
        self._state_machine_by_ip = {}

    def handle_tr069_message(
        self,
        ctx: WsgiMethodContext,
        tr069_message: ComplexModelBase,
    ) -> Any:
        """ Delegate message handling to the appropriate eNB state machine """
        client_ip = self._get_client_ip(ctx)
        if isinstance(tr069_message, models.Inform):
            try:
                self._update_device_mapping(client_ip, tr069_message)
            except UnrecognizedEnodebError as err:
                logger.warning(
                    'Received TR-069 Inform message from an '
                    'unrecognized device. '
                    'Ending TR-069 session with empty HTTP '
                    'response. Error: (%s)', err,
                )
                return models.DummyInput()

        handler = self._get_handler(client_ip)
        if handler is None:
            logger.warning(
                'Received non-Inform TR-069 message from unknown '
                'eNB. Ending session with empty HTTP response.',
            )
            return models.DummyInput()

        return handler.handle_tr069_message(tr069_message)

    def get_handler_by_ip(self, client_ip: str) -> EnodebAcsStateMachine:
        return self._state_machine_by_ip[client_ip]

    def get_handler_by_serial(self, enb_serial: str) -> EnodebAcsStateMachine:
        client_ip = self._ip_serial_mapping.get_ip(enb_serial)
        return self._state_machine_by_ip[client_ip]

    def get_connected_serial_id_list(self) -> List[str]:
        return self._ip_serial_mapping.get_serial_list()

    def get_ip_of_serial(self, enb_serial: str) -> str:
        return self._ip_serial_mapping.get_ip(enb_serial)

    def get_serial_of_ip(self, client_ip: str) -> str:
        serial = self._ip_serial_mapping.get_serial(client_ip)
        return serial or 'default'

    def _get_handler(
        self,
        client_ip: str,
    ) -> EnodebAcsStateMachine:
        return self._state_machine_by_ip[client_ip]

    def _update_device_mapping(
        self,
        client_ip: str,
        inform: models.Inform,
    ) -> None:
        """
        When receiving an Inform message, we can figure out what device we
        are talking to. We can also see if the IP has changed, and the
        StateMachineManager must track this so that subsequent tr069
        messages can be handled correctly.
        """
        enb_serial = self._parse_msg_for_serial(inform)
        if enb_serial is None:
            raise UnrecognizedEnodebError(
                'eNB does not have serial number '
                'under expected param path',
            )
        if not is_enb_registered(self._service.mconfig, enb_serial):
            try:
                self._send_device_info(inform, enb_serial)
            except Exception:
                logger.exception("Sending eNB PnP info failed")
            raise UnrecognizedEnodebError(
                'eNB not registered to this Access '
                'Gateway (serial #%s)' % enb_serial,
            )
        self._associate_serial_to_ip(client_ip, enb_serial)
        handler = self._get_handler(client_ip)
        if handler is None:
            device_name = get_device_name_from_inform(inform)
            handler = self._build_handler(device_name)
            self._state_machine_by_ip[client_ip] = handler

    def _associate_serial_to_ip(
        self,
        client_ip: str,
        enb_serial: str,
    ) -> None:
        """
        If a device/IP combination changes, then the StateMachineManager
        must detect this, and update its mapping of what serial/IP corresponds
        to which handler.
        """
        if self._ip_serial_mapping.has_ip(client_ip):
            # Same IP, different eNB connected
            prev_serial = self._ip_serial_mapping.get_serial(client_ip)
            if enb_serial != prev_serial:
                logger.info(
                    'eNodeB change on IP <%s>, from %s to %s',
                    client_ip, prev_serial, enb_serial,
                )
                self._ip_serial_mapping.set_ip_and_serial(client_ip, enb_serial)
                self._state_machine_by_ip[client_ip] = None
        elif self._ip_serial_mapping.has_serial(enb_serial):
            # Same eNB, different IP
            prev_ip = self._ip_serial_mapping.get_ip(enb_serial)
            if client_ip != prev_ip:
                logger.info(
                    'eNodeB <%s> changed IP from %s to %s',
                    enb_serial, prev_ip, client_ip,
                )
                self._ip_serial_mapping.set_ip_and_serial(client_ip, enb_serial)
                handler = self._state_machine_by_ip[prev_ip]
                self._state_machine_by_ip[client_ip] = handler
                del self._state_machine_by_ip[prev_ip]
        else:
            # TR069 message is coming from a different IP, and a different
            # serial ID. No need to change mapping
            handler = None
            self._ip_serial_mapping.set_ip_and_serial(client_ip, enb_serial)
            self._state_machine_by_ip[client_ip] = handler

    @staticmethod
    def _parse_msg_for_serial(tr069_message: models.Inform) -> Optional[str]:
        """ Return the eNodeB serial ID if it's found in the message """
        if not isinstance(tr069_message, models.Inform):
            return

        # Mikrotik Intercell does not return serial in ParameterList
        if hasattr(tr069_message, 'DeviceId') and \
                hasattr(tr069_message.DeviceId, 'SerialNumber'):
            return tr069_message.DeviceId.SerialNumber

        if not hasattr(tr069_message, 'ParameterList') or \
                not hasattr(tr069_message.ParameterList, 'ParameterValueStruct'):
            return None

        # Parse the parameters
        param_values_by_path = {}
        for param_value in tr069_message.ParameterList.ParameterValueStruct:
            path = param_value.Name
            value = param_value.Value.Data
            param_values_by_path[path] = value

        possible_sn_paths = [
            'Device.DeviceInfo.SerialNumber',
            'InternetGatewayDevice.DeviceInfo.SerialNumber',
        ]
        for path in possible_sn_paths:
            if path in param_values_by_path:
                return param_values_by_path[path]
        return None

    @staticmethod
    def _get_client_ip(ctx: WsgiMethodContext) -> str:
        return ctx.transport.req_env.get("REMOTE_ADDR", "unknown")

    def _build_handler(
        self,
        device_name: EnodebDeviceName,
    ) -> EnodebAcsStateMachine:
        """
        Create a new state machine based on the device type
        """
        device_handler_class = get_device_handler_from_name(device_name)
        acs_state_machine = device_handler_class(self._service)
        return acs_state_machine

    @staticmethod
    def _enb_is_valid(manufacturer, product_class, enb_serial):
        if not manufacturer or not product_class:
            return False

        valid_enb = {
            'Sercomm': {
                # NOTE(oleksandr): FreedomFi One
                'HeNB-TDD-Enterprise': [
                    '[0-9]{4}[a-zA-Z]{2}[0-9]{7}'
                ]
            },
            'Baicells': {
                # NOTE(oleksandr): Nova 430
                'FAP/pBS3101S/SC': [
                    r'\d{12}[A-Z0-9]{2}[a-zA-Z0-9]{1}\d{4}',
                ],
                # NOTE(oleksandr): Nova 436Q
                'FAP/mBS31001/CA': [
                    r'\d{12}[A-Z0-9]{2}[a-zA-Z0-9]{1}\d{4}',
                ],
            }
        }

        for pattern in valid_enb.get(manufacturer, {}).get(product_class, []):
            if re.match(pattern, enb_serial):
                return True

        return False

    def _send_device_info(self, inform: models.Inform, enb_serial):
        device_params = self._retrieve_device_params(inform)
        device_params['serial'] = enb_serial

        if not self._enb_is_valid(device_params['manufacturer'], device_params['productClass'], enb_serial):
            logger.warning('FreedomFi Plug and Play is not yet supported for the eNodeB\n'
                           f'Manufacturer: {device_params["manufacturer"]}\n'
                           f'ProductClass: {device_params["productClass"]}\n'
                           f'eNB serial: {enb_serial}')
            return

        cfg = load_service_config('enodebd')

        with open(cfg['ffi_agw_serial_path'], 'r') as agw_serial_file:
            agw_serial = agw_serial_file.readline()[:-1]

        if not (cfg.get('ffi_pnp_api') and cfg.get('ffi_api_key')):
            logger.warning("eNodeB Plug-n-Play config missing")
            return

        url = cfg['ffi_pnp_api'].format(serialId=agw_serial)
        api_key = cfg['ffi_api_key']

        response = None
        try:
            response = requests.post(url, json=device_params, headers={'X-API-Key': api_key})
            response.raise_for_status()
        except Exception as e:
            logger.warning("Sending eNodeB info failed")
            if response is not None:
                logger.warning(response.text)
            raise

        logger.debug("Successfully sent eNB PnP request:")
        logger.debug(response.text)

    @staticmethod
    def _retrieve_device_params(inform: models.Inform):
        desired_params = {}

        if hasattr(inform, 'DeviceId'):
            if hasattr(inform.DeviceId, 'Manufacturer'):
                desired_params['manufacturer'] = inform.DeviceId.Manufacturer
            if hasattr(inform.DeviceId, 'OUI'):
                desired_params['oui'] = inform.DeviceId.OUI
            if hasattr(inform.DeviceId, 'ProductClass'):
                desired_params['productClass'] = inform.DeviceId.ProductClass

        return desired_params


class IpToSerialMapping:
    """ Bidirectional map between <eNodeB IP> and <eNodeB serial ID> """

    def __init__(self) -> None:
        self.ip_by_enb_serial = {}
        self.enb_serial_by_ip = {}

    def del_ip(self, ip: str) -> None:
        if ip not in self.enb_serial_by_ip:
            raise KeyError('Cannot delete missing IP')
        serial = self.enb_serial_by_ip[ip]
        del self.enb_serial_by_ip[ip]
        del self.ip_by_enb_serial[serial]

    def del_serial(self, serial: str) -> None:
        if serial not in self.ip_by_enb_serial:
            raise KeyError('Cannot delete missing eNodeB serial ID')
        ip = self.ip_by_enb_serial[serial]
        del self.ip_by_enb_serial[serial]
        del self.enb_serial_by_ip[ip]

    def set_ip_and_serial(self, ip: str, serial: str) -> None:
        self.ip_by_enb_serial[serial] = ip
        self.enb_serial_by_ip[ip] = serial

    def get_ip(self, serial: str) -> str:
        return self.ip_by_enb_serial[serial]

    def get_serial(self, ip: str) -> Optional[str]:
        return self.enb_serial_by_ip.get(ip, None)

    def has_ip(self, ip: str) -> bool:
        return ip in self.enb_serial_by_ip

    def has_serial(self, serial: str) -> bool:
        return serial in self.ip_by_enb_serial

    def get_serial_list(self) -> List[str]:
        return list(self.ip_by_enb_serial.keys())

    def get_ip_list(self) -> List[str]:
        return list(self.enb_serial_by_ip.keys())
