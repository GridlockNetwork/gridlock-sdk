import { IGuardian } from "../guardian/guardian.interfaces.js";
import { AccessAndRefreshTokens } from "../auth/auth.interfaces.js";

export interface IUser {
  email: string;
  name?: string;
  role: string;
  isEmailVerified: boolean;
  ownerGuardian: IGuardian;
  nodePool: IGuardian[];
}

export interface INodePoolState {
  action?: string;
  node?: { _id?: string; nodeId?: string; name?: string };
  approvedBy?: { type: string; approved?: boolean; nodeId?: string }[];
}

export interface INodePool {
  _id?: string;
  type: string;
  active: boolean;
  nodeId?: string;
  name: string;
  publicKey?: string;
  model?: string;
  created?: string;
  lastSeen?: string;
  lastResponse?: string;
  deviceId?: string;
  code: string;
  state?: INodePoolState;
  healthStatus?: string;
}

export interface IDeviceInfo {
  versionCode: number;
  platform: string;
  platformVersion: string;
  brand: string;
  model: string;
  totalMemory: number | null;
  batteryLevel: number | null;
  isEmulator: boolean | null;
}

export interface IProtectingUser {
  _id: string;
  name: string;
  nodeId: string;
  profilePhotoUrl?: string;
  nodePool: INodePool[];
  actionRequired?: { type: "restoreAccount"; code: string }; // TODO add enum
}

export interface IMintStatus {
  _id: string;
  transactionId: string;
  productId: string;
  status: string;
  createdDate: string;
  updatedDate: string;
  coins: ICoinStatus[];
}

export interface ICoinStatus {
  _id: string;
  name: string;
  state: string;
  updatedDate: string;
}

export interface IProtectingInvite {
  _id: string;
  nodePoolId: string;
  code: string;
  name: string;
  nodeId: string;
  profilePhotoUrl?: string;
}

export interface IRegisterData {
  email: string;
  name: string;
}

export interface IRegisterResponse {
  user: IUser;
  authTokens: AccessAndRefreshTokens;
}
