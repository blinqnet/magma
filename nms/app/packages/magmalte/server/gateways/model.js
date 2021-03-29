/**
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
 * @flow
 * @format
 */

import Sequelize from 'sequelize';
import {sequelize} from '@fbcnms/sequelize-models';

export type GatewayAttributes = {|
  hardware_id: string,
  challenge_key: string,
  tenant: string,
  network?: string,
  public_ip: string,
  private_ip: string,
|};

const Gateway: Class<Sequelize.Model<GatewayAttributes>> = sequelize.define(
  'Gateway',
  {
    hardware_id: {
      type: Sequelize.UUID,
      allowNull: false,
      primaryKey: true,
    },
    challenge_key: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    tenant: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    network: {
      type: Sequelize.STRING,
      allowNull: true,
    },
    public_ip: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    private_ip: {
      type: Sequelize.STRING,
      allowNull: false,
    },
  },
);

export default Gateway;
