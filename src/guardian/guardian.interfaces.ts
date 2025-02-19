import { IUser } from "../user/user.interfaces.js";

interface IStatus {
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
interface IGuardianStatus {
  name: string;
  lastseen: string;
  regenStatusOK: boolean;
  valid: boolean;
  healthy: boolean;
  lastValidation: string;
  nodeId: string;
  possibleFailingReason: string;
}

export interface IUserStatusResponse {
  email: string;
  userId: string;
  nodeId: string;
  created: string;
  lastLogin: string;
  status: IStatus;
  guardian: IGuardianStatus[];
  user: IUser;
}

export interface IGuardian {
  name: string;
  type:
    | "ownerGuardian"
    | "socialGuardian"
    | "localGuardian"
    | "cloudGuardian"
    | "gridlockGuardian"
    | "partnerGuardian";
  nodeId: string;
  publicKey: string;
  e2ePublicKey: string;
  active: boolean;
}

export interface IReplaceGuardianResponse {
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
  updatedUser: IUser;
}

export interface IAddGuardianParams {
  email: string;
  password: string;
  guardian: IGuardian;
  isOwnerGuardian: boolean;
}
