import * as verifyCommand from './verify';
import * as statusCommand from './status';
import * as adminStatusCommand from './adminstatus';
import * as helpCommand from './help';

export const commands = [
  verifyCommand,
  statusCommand,
  adminStatusCommand,
  helpCommand,
];

export { verifyCommand, statusCommand, adminStatusCommand, helpCommand };