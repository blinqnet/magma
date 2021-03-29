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

const key = fs.readFileSync(
  path.resolve(__dirname, 'keys/public.asc'),
  'utf-8',
);

export type ProvisionFilePayload = {
  [string]: string,
};

export type ParsedProvisionFile = {
  isValid: boolean,
  payload: ProvisionFilePayload,
};

const replaceAll = (
  str: string,
  toBeReplaced: string,
  replaceWith: string,
): string => {
  return str.split(toBeReplaced).join(replaceWith);
};

const parse = async (text: string): Promise<ParsedProvisionFile> => {
  const formatted = replaceAll(text, '\\r\\n', '\n');
  const {signatures, data} = await openpgp.verify({
    message: await openpgp.cleartext.readArmored(formatted),
    publicKeys: (await openpgp.key.readArmored(key)).keys,
  });

  const payload = data.split('\n').reduce((acc, entry) => {
    const [key, value] = entry.split(':');
    return {...acc, [key]: value.trim()};
  }, {});

  return {
    isValid: signatures[0].valid,
    payload,
  };
};

export default parse;
