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

import AddNetworkDialog from './AddNetworkDialog';
import Button from '@fbcnms/ui/components/design-system/Button';
import DeleteIcon from '@material-ui/icons/Delete';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import EditIcon from '@material-ui/icons/Edit';
import EditNetworkDialog from './EditNetworkDialog';
import IconButton from '@material-ui/core/IconButton';
import Link from '@material-ui/core/Link';
import LoadingFiller from '@fbcnms/ui/components/LoadingFiller';
import MagmaV1API from '@fbcnms/magma-api/client/WebClient';
import NestedRouteLink from '@fbcnms/ui/components/NestedRouteLink';
import NoNetworksMessage from '@fbcnms/ui/components/NoNetworksMessage';
import Paper from '@material-ui/core/Paper';
import React from 'react';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import TextField from '@material-ui/core/TextField';
import axios from 'axios';

import Typography from '@material-ui/core/Typography';
import useMagmaAPI from '@fbcnms/ui/magma/useMagmaAPI';
import {Route} from 'react-router-dom';
import {makeStyles} from '@material-ui/styles';
import {sortBy} from 'lodash';
import {useCallback, useState} from 'react';
import {useEnqueueSnackbar} from '@fbcnms/ui/hooks/useSnackbar';
import {useRouter} from '@fbcnms/ui/hooks';

const useStyles = makeStyles(theme => ({
  header: {
    margin: '10px',
    display: 'flex',
    justifyContent: 'space-between',
  },
  paper: {
    margin: '10px',
  },
  noNetworks: {
    height: '70vh',
  },
  noNetworksParagraph: {
    marginBottom: theme.spacing(1),
  },
}));

type DialogConfirmationProps = {
  title: string,
  message: string,
  confirmationPhrase: string,
  label: string,
  onClose: () => void,
  onConfirm: () => void | Promise<void>,
};

function DialogWithConfirmationPhrase(props: DialogConfirmationProps) {
  const [confirmationPhrase, setConfirmationPhrase] = useState('');
  const {title, message, label, onClose, onConfirm} = props;

  return (
    <Dialog open={true} onClose={onClose} onExited={onClose} maxWidth="sm">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>
          {message}
          <TextField
            label={label}
            value={confirmationPhrase}
            onChange={({target}) => setConfirmationPhrase(target.value)}
          />
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button skin="regular" onClick={onClose}>
          Cancel
        </Button>
        <Button
          skin="red"
          onClick={onConfirm}
          disabled={confirmationPhrase !== props.confirmationPhrase}>
          Confirm
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function Networks() {
  const classes = useStyles();
  const enqueueSnackbar = useEnqueueSnackbar();
  const {relativePath, relativeUrl, history} = useRouter();
  const [networks, setNetworks] = useState(null);
  const [networkToDelete, setNetworkToDelete] = useState(null);

  const {error, isLoading} = useMagmaAPI(
    MagmaV1API.getNetworks,
    {},
    useCallback(res => setNetworks(sortBy(res, [n => n.toLowerCase()])), []),
  );

  if (error || isLoading || !networks) {
    return <LoadingFiller />;
  }

  const rows = networks.map(network => (
    <TableRow key={network}>
      <TableCell>{network}</TableCell>
      <TableCell>
        <IconButton
          onClick={() => history.push(relativeUrl(`/edit/${network}`))}>
          <EditIcon />
        </IconButton>
        <IconButton color="primary" onClick={() => setNetworkToDelete(network)}>
          <DeleteIcon />
        </IconButton>
      </TableCell>
    </TableRow>
  ));

  const closeDialog = () => history.push(relativeUrl(''));
  return (
    <div className={classes.paper}>
      <div className={classes.header}>
        <div />
        <NestedRouteLink to="/new">
          <Button>Add Network</Button>
        </NestedRouteLink>
      </div>
      {rows.length === 0 ? (
        <div className={classes.noNetworks}>
          <NoNetworksMessage>
            <Typography className={classes.noNetworksParagraph} variant="h6">
              Seems like nothing is configured in your Orc8r for now!
            </Typography>
            <Typography className={classes.noNetworksParagraph} variant="h6">
              To begin configuring your Private LTE/5G network, please follow
              the steps in this{' '}
              <Link
                target="blank"
                href="https://freedomfi.com/quick-start-guide"
                onClick={e => e.preventDefault}>
                Quick Start Guide
              </Link>
              .
            </Typography>
            <Typography className={classes.noNetworksParagraph} variant="h6">
              We understand that cellular networks are complicated, so if you
              stumble along the way, please join us on{' '}
              <Link
                target="blank"
                href="https://join.slack.com/t/freedomfi/shared_invite/zt-jj6s5ifm-oql1eSudYWrkeJ2Pv7hvFw"
                onClick={e => e.preventDefault}>
                FreedomFi Slack
              </Link>{' '}
              and give us a holler!
            </Typography>
          </NoNetworksMessage>
        </div>
      ) : (
        <Paper elevation={2}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Network ID</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>{rows}</TableBody>
          </Table>
        </Paper>
      )}
      {networkToDelete && (
        <DialogWithConfirmationPhrase
          title="Warning!"
          message={
            'Deleting a network is a serious action and cannot be ' +
            'un-done. Please type the Network ID below if you are confident ' +
            'about this action.'
          }
          label="Network ID"
          confirmationPhrase={networkToDelete}
          onClose={() => setNetworkToDelete(null)}
          onConfirm={async () => {
            const payload = {
              networkID: networkToDelete,
            };
            axios
              .post('/nms/network/delete', payload)
              .then(response => {
                if (!response.data.success) {
                  enqueueSnackbar('Network delete failed', {
                    variant: 'error',
                  });
                }
              })
              .catch(() => {
                enqueueSnackbar('Network delete failed', {
                  variant: 'error',
                });
              });
            setNetworks(networks.filter(n => n != networkToDelete));
            setNetworkToDelete(null);
          }}
        />
      )}
      <Route
        path={relativePath('/new')}
        render={() => (
          <AddNetworkDialog
            onClose={closeDialog}
            onSave={networkID => {
              setNetworks([...networks, networkID]);
              enqueueSnackbar('Network created successfully', {
                variant: 'success',
              });
              closeDialog();
            }}
          />
        )}
      />
      <Route
        path={relativePath('/edit/:networkID')}
        render={() => (
          <EditNetworkDialog
            onClose={closeDialog}
            onSave={_ => {
              enqueueSnackbar('Network updated successfully', {
                variant: 'success',
              });
              closeDialog();
            }}
          />
        )}
      />
    </div>
  );
}

export default Networks;
