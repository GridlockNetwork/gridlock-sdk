import { ApisauceInstance, create } from 'apisauce';
import { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { hashMessage, recoverAddress } from 'ethers';
import { User, RegisterData } from './types/User';
import moment from 'moment';
import { ReplaceGuardianResponse, UserStatusResponse, Guardian } from './types/Guardians';
import { CoinWallet, CreateMultipleWalletResponse } from './types/Wallet';

import nacl from 'tweetnacl';
import pkg from 'tweetnacl-util';

const { decodeUTF8 } = pkg;

import bs58 from 'bs58';

export const ETHEREUM = 'ethereum';
export const SOLANA = 'solana';
export const SUPPORTED_COINS = [ETHEREUM, SOLANA];

interface GridlockSdkProps {
  apiKey: string;
  baseUrl: string;
  verbose: boolean;
  logger: any;
}

interface LoginResponse {
  message: string;
  user: User;
  token: string;
}

interface RegisterResponse {
  message: string;
  user: User;
  token: string;
}

type UnifiedResponse<T> =
  | { success: true; payload: T } // For success
  | { success: false; error: { message: string; code?: number }, raw?: any }; // For failure

class GridlockSdk {
  private apiKey: string;
  private baseUrl: string;
  private verbose: boolean;
  private logger: any;
  private authToken: string = '';
  private retriedRequest: boolean = false; // flag to track if a request has been retried

  api: ApisauceInstance;

  constructor(props: GridlockSdkProps) {
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
      (response: AxiosResponse) => {
        this.log(`-> :${moment().format('HH:mm:ss')}: ${response.config.method?.toUpperCase()}: ${response.config.url} -- ${response.status}`);

        return response;
      },
      async error => {
        this.log(`ERROR-> ${moment().format('HH:mm:ss')}: ${error.config.method?.toUpperCase()}: ${error.config.url} -- ${error?.response?.status}`);
        if (error?.response?.status === 401) {
          if (!this.retriedRequest) {
            this.log('Token expired, trying to refresh it');
            const token = this.authToken;
            const refreshResponse = await this.loginToken(token);

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

  refreshRequestHandler(token: string, nodeId: string, nodePublicKey: string) {
    this.authToken = token;
    this.api = create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: `Bearer ${token || 'undefined'}`,
        nodeId,
        nodePublicKey,
      },
    });
    this.addInterceptors();
  }

  async createUser(registerData: RegisterData): Promise<UnifiedResponse<RegisterResponse>> {
    const response = await this.api.post<UnifiedResponse<RegisterResponse>>('/v1/auth/register', registerData);
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async createWallets(coinTypes: string[]): Promise<UnifiedResponse<CoinWallet[]>> {
    const response = await this.api.post<UnifiedResponse<CoinWallet[]>>('/wallet/create_multiple', { coinTypes });
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async loginToken(token: string): Promise<UnifiedResponse<LoginResponse>> {
    const response = await this.api.post<UnifiedResponse<LoginResponse>>('/login/token', { token });
    if (response.data?.success) {
      const payload = response.data.payload;
      const newToken = payload.token;
      const user = payload.user;
      const nodeId = user.nodeId;
      const nodePublicKey = user.nodePool.find(node => node.nodeId === nodeId)?.publicKey;

      this.refreshRequestHandler(newToken, nodeId, nodePublicKey || '');
    }
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async signMessage(message: string, coinType: string): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<any>>('/transaction/sdk/signMessageSdk', { message, coinType });
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async signTx(tx: string, coinType: string): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<any>>('/transaction/sdk/signTx', { tx, coinType });
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async verifySignature(coinType: string, message: string, signature: string, expectedAddress: string): Promise<UnifiedResponse<boolean>> {
    if (!SUPPORTED_COINS.includes(coinType)) {
      return { success: false, error: { message: 'Invalid coin type' } };
    }

    try {
      if (coinType === ETHEREUM) {
        const messageHash = hashMessage(message);
        const recoveredAddress = recoverAddress(messageHash, signature);

        const isValid = recoveredAddress?.toLowerCase() === expectedAddress?.toLowerCase();

        return { success: true, payload: isValid };
      }

      if (coinType === SOLANA) {
        const messageBytes = decodeUTF8(message);
        const signatureBytes = bs58.decode(signature);
        const addressBytes = bs58.decode(expectedAddress);

        const isVerified = nacl.sign.detached.verify(messageBytes, signatureBytes, addressBytes);
        return { success: true, payload: isVerified };
      }
    } catch (error) {
      return { success: false, error: { message: 'Error trying to check signature' } };
    }

    return { success: false, error: { message: 'Unsupported coin type' } };
  }

  async getNodes(): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<UserStatusResponse>>('monitoring/userStatusV2');
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async getUser(): Promise<UnifiedResponse<User>> {
    const response = await this.api.get<UnifiedResponse<User>>('/user');
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async getWallets(): Promise<UnifiedResponse<CoinWallet[]>> {
    const response = await this.api.get<UnifiedResponse<CoinWallet[]>>('/wallet');
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async deleteUser(): Promise<UnifiedResponse<any>> {
    const response = await this.api.delete<UnifiedResponse<any>>('/user/safe');
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async addUserGuardian(data: { name: string }): Promise<UnifiedResponse<Omit<ReplaceGuardianResponse, 'state'>>> {
    const response = await this.api.post<UnifiedResponse<Omit<ReplaceGuardianResponse, 'state'>>>('user/guardian/add', data);
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async generateGuardianDeeplink(params: any): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<any>>('/user/generateLink', { params });
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async getGridlockGuardian(): Promise<UnifiedResponse<Guardian>> {
    const response = await this.api.get<UnifiedResponse<Guardian>>('/sdk/guardian/gridlock');
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }

  async getPartnerGuardian(): Promise<UnifiedResponse<Guardian>> {
    const response = await this.api.get<UnifiedResponse<Guardian>>('/sdk/guardian/partner');
    if (response.data?.success !== undefined) {
      return response.data;
    }
    return { success: false, error: { message: 'Unknown error', code: response.status }, raw: response.data };
  }
}

export default GridlockSdk;
