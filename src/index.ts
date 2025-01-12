import { ApisauceInstance, create } from 'apisauce';
import { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import argon2 from 'argon2';
import { hashMessage, recoverAddress } from 'ethers';
import { User, RegisterData } from './types/User';
import moment from 'moment';
import { ReplaceGuardianResponse, UserStatusResponse, Guardian } from './types/Guardians';
import { CoinWallet, CreateMultipleWalletResponse } from './types/Wallet';

import nacl from 'tweetnacl';
import pkg from 'tweetnacl-util';

const { decodeUTF8 } = pkg;

import bs58 from 'bs58';
import { MongoClient, Db } from 'mongodb';

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

interface MongoDBConfig {
  uri: string;
  dbName: string;
}

type UnifiedResponse<T> =
  | { success: true; payload: T } // For success
  | { success: false; error: { message: string; code?: number } }; // For failure

class GridlockSdk {
  private apiKey: string;
  private baseUrl: string;
  private verbose: boolean;
  private logger: any;
  private authToken: string = '';
  private retriedRequest: boolean = false; // flag to track if a request has been retried
  private mongoClient: MongoClient | null = null;
  private db: Db | null = null;

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

    process.on('SIGINT', async () => {
      if (this.mongoClient) {
        await this.mongoClient.close();
        console.log('MongoDB connection closed');
      }
      process.exit(0);
    });
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
            const refreshResponse = await this.refreshToken(token);

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

  // could be avoided // TODO - remove this
  // private hashPassword = async (password: string, salt: string) => {
  //   const options = {
  //     type: argon2.argon2d, // Use Argon2d variant
  //     memoryCost: 1024, // Use 1 MB of memory
  //     timeCost: 2, // Perform 1 iteration
  //     parallelism: 1, // Use 1 thread
  //     hashLength: 24, // Output hash length is 24 bytes
  //   };

  //   const hash = await argon2.hash(password, { salt: Buffer.from(salt, 'hex'), ...options });

  //   return hash;
  // };

  async initDb(mongoConfig: MongoDBConfig): Promise<void> {
    if (!mongoConfig || !mongoConfig.uri || !mongoConfig.dbName) {
      throw new Error('MongoDB configuration is incomplete');
    }

    if (!mongoConfig.uri.startsWith('mongodb://') && !mongoConfig.uri.startsWith('mongodb+srv://')) {
      throw new Error('Invalid MongoDB URI scheme');
    }

    this.mongoClient = new MongoClient(mongoConfig.uri);
    try {
      await this.mongoClient.connect();
    } catch (err) {
      console.error('Failed to connect to MongoDB:', err);
      throw err;  // Stop execution if connection fails
    }
    this.db = this.mongoClient.db(mongoConfig.dbName);
    this.log('MongoDB connected successfully');
  }

  async closeDb(): Promise<void> {
    if (this.mongoClient) {
      await this.mongoClient.close();
      this.log('MongoDB connection closed on SDK');
    }
  }

  async createUser(registerData: RegisterData): Promise<UnifiedResponse<RegisterResponse>> {
    const response = await this.api.post<UnifiedResponse<RegisterResponse>>('/sdk/user/register', registerData);
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async createWallets(coinTypes: string[]): Promise<UnifiedResponse<CoinWallet[]>> {
    const response = await this.api.post<UnifiedResponse<CoinWallet[]>>('/wallet/create_multiple', { coinTypes });
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async refreshToken(token: string): Promise<UnifiedResponse<LoginResponse>> {
    const response = await this.api.post<UnifiedResponse<LoginResponse>>('/login/token', { token });
    if (response.data?.success) {
      const payload = response.data.payload;
      const newToken = payload.token;
      const user = payload.user;
      const nodeId = user.nodeId;
      const nodePublicKey = user.nodePool.find(node => node.nodeId === nodeId)?.publicKey;

      this.refreshRequestHandler(newToken, nodeId, nodePublicKey || '');
    }
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async signMessage(message: string, coinType: string): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<any>>('/transaction/sdk/signMessageSdk', { message, coinType });
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async signTx(tx: string, coinType: string): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<any>>('/transaction/sdk/signTx', { tx, coinType });
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
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

  // async getNetworkStatus(): Promise<UnifiedResponse<UserStatusResponse>> {
  //   const response = await this.api.post<UnifiedResponse<UserStatusResponse>>('monitoring/userStatusV2');
  //   return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  // }

  async getNodes(): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<UserStatusResponse>>('monitoring/userStatusV2');
    if (!response.data?.success) {
      return { success: false, error: { message: response.data?.error?.message || 'No response data', code: response.status } };
    }

    const payload = response.data.payload;
    const user = payload.user;
    if (!user) return { success: false, error: { message: 'User not defined in response' } };

    const nodePool = user.nodePool;
    const guardianData = payload.guardian;

    const types = {
      userGuardian: 'userGuardian',
      gridlockGuardian: 'gridlock',
      ownerGuardian: 'owner',
      partnerGuardian: 'partner',
    };

    const nodes = guardianData.map(guardian => {
      const node = nodePool.find(node => node.nodeId === guardian.nodeId);
      return {
        nodeType: types[node?.type as keyof typeof types] || '',
        nodeId: guardian.nodeId,
        name: guardian.name,
        status: guardian.healthy ? 'Active' : 'Inactive',
        lastseen: guardian.lastseen,
      };
    });

    return { success: true, payload: nodes };
  }

  async getUser(): Promise<UnifiedResponse<User>> {
    const response = await this.api.get<UnifiedResponse<User>>('/user');
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async getWallets(): Promise<UnifiedResponse<CoinWallet[]>> {
    const response = await this.api.get<UnifiedResponse<CoinWallet[]>>('/wallet');
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async deleteUser(): Promise<UnifiedResponse<any>> {
    const response = await this.api.delete<UnifiedResponse<any>>('/user/safe');
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async addUserGuardian(data: { name: string }): Promise<UnifiedResponse<Omit<ReplaceGuardianResponse, 'state'>>> {
    const response = await this.api.post<UnifiedResponse<Omit<ReplaceGuardianResponse, 'state'>>>('user/guardian/add', data);
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async generateGuardianDeeplink(params: any): Promise<UnifiedResponse<any>> {
    const response = await this.api.post<UnifiedResponse<any>>('/user/generateLink', { params });
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }
  async addGuardianToNetwork(guardian: Guardian): Promise<UnifiedResponse<any>> {

    if (!this.db) {
      return { success: false, error: { message: 'Database not initialized' } };
    }

    try {
      const collection = this.db.collection('guardians');
      const result = await collection.insertOne({
        ...guardian,
        model: 'sdk',
        active: true,
      });

      return { success: true, payload: result.insertedId };
    } catch (error) {
      return { success: false, error: { message: (error as Error).message } };
    }
  }


  async showNetwork(): Promise<UnifiedResponse<any>> {

    if (!this.db) {
      return { success: false, error: { message: 'Database not initialized' } };
    }
    try {
      const collection = this.db.collection('guardians');
      const guardians = await collection.find({}).toArray();
      return { success: true, payload: guardians };
    } catch (error) {
      return { success: false, error: { message: (error as Error).message } };
    }
  }

  async getGridlockGuardian(): Promise<UnifiedResponse<Guardian>> {
    const response = await this.api.get<UnifiedResponse<Guardian>>('/sdk/guardian/gridlock');
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }

  async getPartnerGuardian(): Promise<UnifiedResponse<Guardian>> {
    const response = await this.api.get<UnifiedResponse<Guardian>>('/sdk/guardian/partner');
    return response.data || { success: false, error: { message: 'No response data', code: response.status } };
  }
}

export default GridlockSdk;
