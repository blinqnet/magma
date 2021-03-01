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

import express from 'express';
import fs from 'fs';
import sign from './provisionFile/sign';
import {AccessRoles} from '@fbcnms/auth/roles';
import {access} from '@fbcnms/auth/access';
import type {ExpressResponse} from 'express';
import type {FBCNMSRequest} from '@fbcnms/auth/access';
const logger = require('@fbcnms/logging').getLogger(module);

const {ADDITIONAL_PROVISION_FILE_PAYLOAD_FILENAME} = process.env;

const router: express.Router<FBCNMSRequest, ExpressResponse> = express.Router();

router.get('/', access(AccessRoles.USER), async (req, res) => {
  const {name: currentTenant, isMasterOrg} = await req.organization();

  const filePayload =
    isMasterOrg && typeof req.query?.tenant === 'string'
      ? `tenant: ${req.query.tenant}`
      : `tenant: ${currentTenant}`;

  if (ADDITIONAL_PROVISION_FILE_PAYLOAD_FILENAME) {
    try {
      const additionalPayloadBuffer = await fs.promises.readFile(
        ADDITIONAL_PROVISION_FILE_PAYLOAD_FILENAME,
      );
      const additionalPayload = additionalPayloadBuffer.toString().trim();

      if (!!additionalPayload) {
        filePayload = basePayload + '\n' + additionalPayload;
      } else {
        filePayload = basePayload;
      }
    } catch (e) {
      logger.error(e);
      filePayload = basePayload;
    }
  } else {
    filePayload = basePayload;
  }

  res.statusCode = 200;
  res.attachment('freedomfi.lic');
  res.send(await sign(filePayload));
});

export default router;
