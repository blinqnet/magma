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

import Gateway from './model';
import express from 'express';
import parseProvisionFileContent from '../gatewayProvisioning/provisionFile/parse';
import {AccessRoles} from '@fbcnms/auth/roles';
import {ValidationError} from 'sequelize';
import {access} from '@fbcnms/auth/access';
import {formatSequelizeErrors} from './utils';
import type {ExpressResponse} from 'express';
import type {FBCNMSRequest} from '@fbcnms/auth/access';
import type {GatewayAttributes} from './model';

const router: express.Router<FBCNMSRequest, ExpressResponse> = express.Router();

export type POSTGatewayBody = {|
  hardware_id: string,
  challenge_key: string,
  provision_file: string,
  network?: string,
  public_ip: string,
  private_ip: string,
|};

router.post('/', access(AccessRoles.SUPERUSER), async (req, res) => {
  const {provision_file, ...rest}: POSTGatewayBody = req.body;

  try {
    const {isValid, payload} = await parseProvisionFileContent(provision_file);

    if (isValid) {
      const gatewayAttributes = {
        ...rest,
        tenant: payload.tenant,
      };

      const newGateway = await Gateway.upsert(gatewayAttributes);
      res.statusCode = 201;
      res.end(JSON.stringify(newGateway));
    } else {
      res.statusCode = 400;
      res.end('Provision file invalid.');
    }
  } catch (e) {
    if (e instanceof ValidationError) {
      res.statusCode = 400;
      res.end(JSON.stringify(formatSequelizeErrors(e.errors)));
    } else {
      res.statusCode = 500;
      res.end();
    }
  }
});

router.put('/:id', access(AccessRoles.USER), async (req, res) => {
  const {id: hardware_id} = req.params;
  const {name: tenant, isMasterOrg} = await req.organization();
  const sendAttributes: GatewayAttributes = req.body;

  const filter = isMasterOrg ? {hardware_id} : {hardware_id, tenant};

  try {
    const gateway = await Gateway.findOne({where: filter});
    const attributesToSet = isMasterOrg
      ? sendAttributes
      : {...sendAttributes, tenant: gateway?.getDataValue('tenant')};

    if (!gateway) {
      res.statusCode = 404;
      res.end();
    } else {
      await gateway.update(attributesToSet);

      res.statusCode = 204;
      res.end();
    }
  } catch (e) {
    res.statusCode = 500;
    res.end();
  }
});

type PatchGatewayPayload = {|
  hardware_id?: string,
  challenge_key?: string,
  tenant?: string,
  network?: string,
  public_ip?: string,
  private_ip?: string,
|};

router.patch('/:id', access(AccessRoles.USER), async (req, res) => {
  const {id: hardware_id} = req.params;
  const {name: tenant, isMasterOrg} = await req.organization();
  const sentAttributes: PatchGatewayPayload = req.body;

  const filter = isMasterOrg ? {hardware_id} : {hardware_id, tenant};

  try {
    const gateway = await Gateway.findOne({where: filter});
    if (!isMasterOrg && 'tenant' in sentAttributes) {
      delete sentAttributes.tenant;
    }
    if (!gateway) {
      res.statusCode = 404;
      res.end();
    } else {
      await gateway.update(sentAttributes);

      res.statusCode = 204;
      res.end();
    }
  } catch (e) {
    res.statusCode = 500;
    res.end();
  }
});

router.get('/', access(AccessRoles.USER), async (req, res) => {
  try {
    const {name: tenant, isMasterOrg} = await req.organization();
    const filter = isMasterOrg
      ? {}
      : {
          where: {
            tenant,
          },
        };

    const gateways = await Gateway.findAll(filter);

    res.statusCode = 200;
    res.end(JSON.stringify(gateways));
  } catch (e) {
    res.statusCode = 500;
    res.end();
  }
});

router.get('/:id', access(AccessRoles.USER), async (req, res) => {
  const {id: hardware_id} = req.params;
  const {name: tenant, isMasterOrg} = await req.organization();

  const filter = isMasterOrg ? {hardware_id} : {hardware_id, tenant};

  try {
    const gateway = await Gateway.findOne({where: filter});

    if (!gateway) {
      res.statusCode = 404;
      res.end();
    } else {
      res.statusCode = 200;
      res.end(JSON.stringify(gateway));
    }
  } catch (e) {
    res.statusCode = 500;
    res.end();
  }
});

router.delete('/:id', access(AccessRoles.USER), async (req, res) => {
  const {id: hardware_id} = req.params;
  const {name: tenant, isMasterOrg} = await req.organization();

  const filter = isMasterOrg ? {hardware_id} : {hardware_id, tenant};

  try {
    const gateway = await Gateway.findOne({where: filter});

    if (!gateway) {
      res.statusCode = 404;
      res.end();
    } else {
      const deleted = await gateway.destroy();

      if (deleted) {
        res.statusCode = 204;
        res.end();
      } else {
        throw new Error();
      }
    }
  } catch (e) {
    res.statusCode = 500;
    res.end();
  }
});

export default router;
