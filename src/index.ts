import { ApisauceInstance, create } from 'apisauce';
import { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { hashMessage, recoverAddress } from 'ethers';
import { IUser, IRegisterData } from './types/User';
import moment from 'moment';
import { IReplaceGuardianResponse, IUserStatusResponse, IGuardian } from './types/Guardians';
import { ICoinWallet } from './types/Wallet';

import nacl from 'tweetnacl';
import pkg from 'tweetnacl-util';

const { decodeUTF8 } = pkg;

import bs58 from 'bs58';

export const ETHEREUM = 'ethereum';
export const SOLANA = 'solana';
export const SUPPORTED_COINS = [ETHEREUM, SOLANA];

interface IGridlockSdkProps {
  apiKey: string;
  baseUrl: string;
  verbose: boolean;
  logger: any;
}

interface ILoginResponse {
  tokens: {
    access: {
      token: string;
      expires: string;
    };
    refresh: {
      token: string;
      expires: string;
    };
  };
}

interface IRegisterResponse {
  message: string;
  user: IUser;
  token: string;
}

type IUnifiedResponse<T> =
  | { success: true; data: T } // For success
  | { success: false; error: { message: string; code?: number }, raw?: any }; // For failure

class GridlockSdk {
  private apiKey: string;
  private baseUrl: string;
  private verbose: boolean;
  private logger: any;
  private authToken: string = '';
  private retriedRequest: boolean = false; // flag to track if a request has been retried

  api: ApisauceInstance;

  constructor(props: IGridlockSdkProps) {
    this.apiKey = props.apiKey;
    this.baseUrl = props.baseUrl;
    this.verbose = props.verbose;
    this.logger = props.logger || console;

    this.api = create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: 'Bearer undefined',
      },
      withCredentials: true,
      timeout: 60000,
    });

    this.addInterceptors();
  }

  private generateNodeId() {
    return uuidv4();
  }

  private generateDummyPublicKey = (length: number = 56) => {
    let key = '';
    while (key.length < length) {
      const rawKey = crypto // use crypto to ensure true randomness
        .randomBytes(Math.ceil((length * 3) / 4))
        .toString('base64')
        .replace(/[^A-Z0-9]/gi, '')
        .toUpperCase();

      key += rawKey;
    }

    return key.slice(0, length);
  };

  private log = (...args: any[]) => {
    if (!this.logger || !this.verbose) return;

    this.logger.log('\n');
    this.logger.log(...args);
  };

  private addInterceptors = () => {
    this.api.axiosInstance.interceptors.request.use(request => {
      this.log(`<- ${moment().format('HH:mm:ss')}: ${request.method?.toUpperCase()}: ${request.url} `);
      return request;
    });

    this.api.axiosInstance.interceptors.response.use(
      (response) => {
        this.log(`-> :${moment().format('HH:mm:ss')}: ${response.config.method?.toUpperCase()}: ${response.config.url} -- ${response.status}`);
        return response;
      },
      async error => {
        this.log(`ERROR-> ${moment().format('HH:mm:ss')}: ${error.config.method?.toUpperCase()}: ${error.config.url} -- ${error?.response?.status}`);
        if (error?.response?.status === 401) {
          if (!this.retriedRequest) {
            this.log('Token expired, trying to refresh it');
            const token = this.authToken;
            const refreshResponse = await this.loginWithToken(token);

            if (refreshResponse) {
              // retry the original request with the new token
              error.config.headers['Authorization'] = `Bearer ${this.authToken}`;
              this.retriedRequest = true;
              return this.api.axiosInstance.request(error.config);
            }
          }
        }
        this.retriedRequest = false;
        return Promise.reject(error);
      },
    );
  };

  refreshRequestHandler(token: string) {
    // console.log('Old Auth Token:', this.authToken); //debug //this doesn't persist across cli commands. It's always undefined. i think it's because the sdk is reinitialized every time
    // console.log('New Token:', token); //debug
    this.authToken = token;
    this.api = create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: `Bearer ${token || 'undefined'}`,
      },
    });
    this.addInterceptors();
  }

  async createUser(registerData: IRegisterData): Promise<IUnifiedResponse<IRegisterResponse>> {
    const response = await this.api.post<IRegisterResponse>('/v1/auth/register', registerData);
    return this.toUnifiedResponse<IRegisterResponse>(response);
  }

  async createWallets(blockchain: string[], user: IUser): Promise<IUnifiedResponse<ICoinWallet[]>> {
    const response = await this.api.post<ICoinWallet[]>('/v1/wallets', { blockchain, user });
    return this.toUnifiedResponse<ICoinWallet[]>(response);
  }

  async loginWithToken(refreshToken: string): Promise<IUnifiedResponse<ILoginResponse>> {
    const response = await this.api.post<ILoginResponse>('/v1/auth/refresh-tokens', { refreshToken });
    if (response.status && response.status >= 200 && response.status < 300) {
      const newToken = response.data?.tokens.access.token;
      if (newToken) {
        this.refreshRequestHandler(newToken);
      }
    }
    return this.toUnifiedResponse<ILoginResponse>(response);
  }

  async sign(message: string, wallet: string, user: IUser): Promise<IUnifiedResponse<any>> {
    const response = await this.api.post<any>('/v1/wallets/sign', { message, wallet, user });
    return this.toUnifiedResponse<any>(response);
  }

  async signTx(tx: string, coinType: string): Promise<IUnifiedResponse<any>> {
    const response = await this.api.post<any>('/transaction/sdk/signTx', { tx, coinType });
    return this.toUnifiedResponse<any>(response);
  }

  async verifySignature(coinType: string, message: string, signature: string, expectedAddress: string): Promise<IUnifiedResponse<boolean>> {
    if (!SUPPORTED_COINS.includes(coinType)) {
      return { success: false, error: { message: 'Invalid coin type' } };
    }

    try {
      if (coinType === ETHEREUM) {
        const messageHash = hashMessage(message);
        const recoveredAddress = recoverAddress(messageHash, signature);
        const isValid = recoveredAddress?.toLowerCase() === expectedAddress?.toLowerCase();
        return { success: true, data: isValid };
      }

      if (coinType === SOLANA) {
        const messageBytes = decodeUTF8(message);
        const signatureBytes = bs58.decode(signature);
        const addressBytes = bs58.decode(expectedAddress);
        const isVerified = nacl.sign.detached.verify(messageBytes, signatureBytes, addressBytes);
        return { success: true, data: isVerified };
      }
    } catch (error) {
      return { success: false, error: { message: 'Error trying to check signature' } };
    }

    return { success: false, error: { message: 'Unsupported coin type' } };
  }

  async getNodes(): Promise<IUnifiedResponse<any>> {
    const response = await this.api.post<IUserStatusResponse>('monitoring/userStatusV2');
    return this.toUnifiedResponse<IUserStatusResponse>(response);
  }

  async getUser(): Promise<IUnifiedResponse<IUser>> {
    const response = await this.api.get<IUser>('/user');
    return this.toUnifiedResponse<IUser>(response);
  }

  async getWallets(): Promise<IUnifiedResponse<ICoinWallet[]>> {
    const response = await this.api.get<ICoinWallet[]>('/wallet');
    return this.toUnifiedResponse<ICoinWallet[]>(response);
  }

  async deleteUser(): Promise<IUnifiedResponse<any>> {
    const response = await this.api.delete<any>('/user/safe');
    return this.toUnifiedResponse<any>(response);
  }

  async addUserGuardian(data: { name: string }): Promise<IUnifiedResponse<Omit<IReplaceGuardianResponse, 'state'>>> {
    const response = await this.api.post<Omit<IReplaceGuardianResponse, 'state'>>('user/guardian/add', data);
    return this.toUnifiedResponse<Omit<IReplaceGuardianResponse, 'state'>>(response);
  }

  async generateGuardianDeeplink(params: any): Promise<IUnifiedResponse<any>> {
    const response = await this.api.post<any>('/user/generateLink', { params });
    return this.toUnifiedResponse<any>(response);
  }

  async getGridlockGuardian(): Promise<IUnifiedResponse<IGuardian>> {
    const response = await this.api.get<IGuardian>('/sdk/guardian/gridlock');
    return this.toUnifiedResponse<IGuardian>(response);
  }

  async getPartnerGuardian(): Promise<IUnifiedResponse<IGuardian>> {
    const response = await this.api.get<IGuardian>('/sdk/guardian/partner');
    return this.toUnifiedResponse<IGuardian>(response);
  }

  async loginWithKey(user: IUser, privateKeyBuffer: string): Promise<IUnifiedResponse<ILoginResponse>> {
    try {
      const { nodeId } = user.ownerGuardian;
      const nonceResponse = await this.api.post<{ nonce: string }>('/v1/auth/nonce', { nodeId });

      if (!nonceResponse.data || !nonceResponse.data.nonce) {
        return { success: false, error: { message: 'Failed to get nonce', code: nonceResponse.status }, raw: nonceResponse.data };
      }
      const nonce = nonceResponse.data.nonce;

      const signature = crypto.sign(null, Buffer.from(nonce, 'hex'), {
        key: privateKeyBuffer,
        format: 'der',
        type: 'pkcs8',
      });

      const loginResponse = await this.api.post<ILoginResponse>('/v1/auth/login', { user, signature: signature.toString('base64') });
      if (loginResponse.status && loginResponse.status >= 200 && loginResponse.status < 300) {
        const newToken = loginResponse.data?.tokens.access.token;
        if (newToken) {
          this.refreshRequestHandler(newToken);
        }
      }

      return this.toUnifiedResponse<ILoginResponse>(loginResponse);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: { message: errorMessage, code: 500 } };
    }
  }

  async addGuardian(guardian: IGuardian): Promise<IUnifiedResponse<any>> {
    const response = await this.api.post<any>('/v1/users/addGuardian', guardian);
    return this.toUnifiedResponse<any>(response);
  }

  private toUnifiedResponse<T>(response: ApisauceInstance['post'] extends (...args: any[]) => Promise<infer R> ? R : never): IUnifiedResponse<T> {
    if (response.ok) {
      return { success: true, data: response.data as T };
    } else {
      return { success: false, error: { message: response.problem || 'Unknown error', code: response.status }, raw: response.data };
    }
  }
}

export default GridlockSdk;