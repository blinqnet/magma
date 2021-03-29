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
 * @flow strict-local
 * @format
 */
'use strict';

import {} from './common/axiosConfig';
import LoginForm from '@fbcnms/ui/components/auth/LoginForm.js';
import React from 'react';
import ReactDOM from 'react-dom';
import logo from './assets/magma-logo.png';
import nullthrows from '@fbcnms/util/nullthrows';
import {AppContextProvider} from '@fbcnms/ui/context/AppContext';
import {BrowserRouter} from 'react-router-dom';
import {makeStyles} from '@material-ui/styles';
import {useHistory} from 'react-router';

const useStyles = makeStyles(_theme => ({
  logo: {
    width: '70%',
    marginTop: '10px',
    marginBottom: '-20px',
  },
}));

function LoginWrapper() {
  const history = useHistory();
  const styles = useStyles();
  return (
    <LoginForm
      // eslint-disable-next-line no-warning-comments
      // $FlowFixMe - createHref exists
      action={history.createHref({pathname: '/user/login'})}
      title={<img className={styles.logo} src={logo} />}
      // eslint-disable-next-line no-warning-comments
      // $FlowFixMe - createHref exists
      ssoAction={history.createHref({pathname: '/user/login/saml'})}
      ssoEnabled={window.CONFIG.appData.ssoEnabled}
      csrfToken={window.CONFIG.appData.csrfToken}
    />
  );
}

ReactDOM.render(
  <AppContextProvider>
    <BrowserRouter>
      <LoginWrapper />
    </BrowserRouter>
  </AppContextProvider>,
  nullthrows(document.getElementById('root')),
);
