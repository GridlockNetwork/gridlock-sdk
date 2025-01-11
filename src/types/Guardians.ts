import { User } from './User';

interface Status {
  degraded: boolean;
  healthyGuardians: number;
  regenOkGuardians: number;
  total: number;
  pg: boolean;
  healthyPG: boolean;
  message: string[];
  warningLevel: string;
  membership: {
    type: string;
    updated: string;
  };
  coins: {
    solana: number;
  };
  balance: number;
  nftCount: number;
  nftEthereum: number;
  nftSolana: number;
}
interface GuardianStatus {
  name: string;
  lastseen: string;
  regenStatusOK: boolean;
  valid: boolean;
  healthy: boolean;
  lastValidation: string;
  nodeId: string;
  possibleFailingReason: string;
}

export interface UserStatusResponse {
  email: string;
  userId: string;
  nodeId: string;
  created: string;
  lastLogin: string;
  status: Status;
  guardian: GuardianStatus[];
  user: User;
}

export interface Guardian {
  nodeId: string;
  name: string;
  type: string;
  active: boolean;
  publicKey: string;
}

export interface ReplaceGuardianResponse {
  status: string;
  code: string;
  newNode: {
    name: string;
    type: string;
    active: boolean;
    code: string;
  };
  state: {
    action: string;
    node: string;
    approvedBy: string[];
  };
  updatedUser: User;
}
