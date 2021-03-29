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
 * @flow
 * @format
 */

import * as openpgp from 'openpgp';
import fs from 'fs';
import path from 'path';

const passphrase = 'asdjG123Hdaj316dhH';
const key = fs.readFileSync(
  path.resolve(__dirname, 'keys/private.asc'),
  'utf-8',
);

const sign = async (payload: string): Promise<string> => {
  const {
    keys: [privateKey],
  } = await openpgp.key.readArmored(key);
  await privateKey.decrypt(passphrase);

  const {data: cleartext} = await openpgp.sign({
    message: openpgp.cleartext.fromText(payload),
    privateKeys: [privateKey],
  });

  return cleartext;
};

export default sign;
