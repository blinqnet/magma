import json
import os
from datetime import datetime

import snowflake
from orc8r.protos.eventd_pb2 import Event

from magma.enodebd.data_models.data_model_parameters import ParameterName
from magma.enodebd.device_config.enodeb_configuration import EnodebConfiguration
from magma.enodebd.state_machines.enb_acs_states import EndSessionState
from magma.eventd.eventd_client import log_event


class FreedomFiEndSesstionState(EndSessionState):
    INFORM_COUNTER_CONFIG_KEY = 'ffi_status_interval'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not hasattr(self.acs, '_inform_counter'):
            self.acs._inform_counter = 0
            self.acs._status_send_interval = int(self.acs.service_config.get(self.INFORM_COUNTER_CONFIG_KEY, 12))

    def enter(self) -> None:
        self._process_inform_counter()

    def _process_inform_counter(self) -> None:
        if self.acs._status_send_interval == 0:
            return

        self.acs._inform_counter += 1
        if self.acs._inform_counter < self.acs._status_send_interval:
            return

        self.acs._inform_counter = 0
        log_event(
            Event(
                stream_name="magmad",
                event_type="enodeb_status",
                tag=snowflake.snowflake(),
                value=json.dumps(gather_enodeb_status(self.acs.device_cfg)),
            ),
        )


def gather_enodeb_status(device_cfg: EnodebConfiguration) -> dict:
    return {
        'hotspot_type': 'enodeb',
        'pubkey': os.environ.get('MINER_PUBKEY', ''),
        'cbsd_id': '{}{}'.format(device_cfg.get_parameter(ParameterName.SAS_FCC_ID),
                                device_cfg.get_parameter(ParameterName.SERIAL_NUMBER)),
        'cell_id': int(device_cfg.get_parameter(ParameterName.CELL_ID)),
        'timestamp': datetime.now().astimezone().replace(microsecond=0).isoformat(),
        'longitude': float(device_cfg.get_parameter(ParameterName.GPS_LONG)),
        'latitude': float(device_cfg.get_parameter(ParameterName.GPS_LAT)),
        'operation_mode': bool(device_cfg.get_parameter(ParameterName.RF_TX_STATUS)),
        'cbsd_category': str(device_cfg.get_parameter(ParameterName.SAS_CBSD_CATEGORY)).upper(),
    }
