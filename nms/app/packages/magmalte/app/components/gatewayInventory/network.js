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
import type {ProvisionedGateway} from './types';

export const getGateways = async (): Promise<Array<ProvisionedGateway>> => {
  const response = await fetch('/gateways');
  return await response.json();
};

type PatchGatewayPayload = {
  private_ip?: string,
  public_ip?: string,
  network?: string | null,
  hardware_id?: string,
  challenge_key?: string,
};

export const patchGateway = async (
  id: string,
  payload: PatchGatewayPayload,
): Promise<Response> => {
  return await fetch(`/gateways/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    headers: {'Content-Type': 'application/json'},
  });
};
