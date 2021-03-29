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

import {getGateways} from './network';
import {useEffect, useState} from 'react';
import type {ProvisionedGateway} from './types';

type UseProvisionedGatewaysFetch = () => {
  isLoading: boolean,
  hasError: boolean,
  gateways: Array<ProvisionedGateway>,
};

const useProvisionedGatewaysFetch: UseProvisionedGatewaysFetch = () => {
  const [gateways, setGateways] = useState<Array<ProvisionedGateway>>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);

  const fetchGateways = async (): Promise<void> => {
    try {
      setIsLoading(true);
      const gateways = await getGateways();

      setGateways(gateways);
      setIsLoading(false);
    } catch {
      setIsLoading(false);
      setHasError(true);
    }
  };

  useEffect(() => {
    fetchGateways();
  }, []);

  return {
    isLoading,
    gateways,
    hasError,
  };
};

export default useProvisionedGatewaysFetch;
