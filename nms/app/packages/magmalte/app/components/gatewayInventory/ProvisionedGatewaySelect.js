/*
 * Copyright 2020 The Magma Authors.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @flow strict-local
 * @format
 */
import MenuItem from '@material-ui/core/MenuItem';
import React from 'react';
import Select from '@material-ui/core/Select';
import useProvisionedGatewaysFetch from './useProvisionedGatewaysFetch';
import {AltFormField} from '../FormField';
import type {ProvisionedGateway} from './types';

type Props = {
  onChange: (gateway: ?ProvisionedGateway | null) => void,
};

const ProvisionedGatewaysSelect = (props: Props) => {
  const {isLoading, hasError, gateways} = useProvisionedGatewaysFetch();

  const getSelectOptions = () => {
    return gateways
      .filter(gw => !gw.network)
      .map(({hardware_id, private_ip}) => (
        <MenuItem value={hardware_id}>
          {hardware_id} | Private IP: {private_ip}
        </MenuItem>
      ));
  };

  return (
    !isLoading &&
    !hasError && (
      <AltFormField label="Registered Gateway">
        <Select
          onChange={({target}) => {
            props.onChange(
              target.value === 'addNew'
                ? null
                : gateways.find(gw => target.value === gw.hardware_id),
            );
          }}
          variant="outlined"
          defaultValue="addNew"
          fullWidth>
          <MenuItem value="addNew">Add new</MenuItem>
          {getSelectOptions()}
        </Select>
      </AltFormField>
    )
  );
};

export default ProvisionedGatewaysSelect;
