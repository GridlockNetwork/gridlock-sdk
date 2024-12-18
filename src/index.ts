import { ApisauceInstance, create } from 'apisauce';
import { AxiosResponse } from 'axios';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import argon2 from 'argon2';
import { hashMessage, recoverAddress } from 'ethers';
import { User } from './types/User';
import moment from 'moment';
import { ReplaceGuardianResponse, UserStatusResponse } from './types/Guardians';
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

  async createUser(registerData: User, verbose: boolean = false) {
    const nodeId = this.generateNodeId();
    const nodePublicKey = this.generateDummyPublicKey();

    // const password = await this.hashPassword(data.password, 'gridlock_hub');

    const requestData = {
      ...registerData,
      nodeId,
      nodePublicKey,
    };

    const response = await this.api.post<RegisterResponse>('/user/sdk/register', requestData);

    if (!response.ok) {
      if (verbose) {
        this.log(`Error trying to create user:\n${response.problem}\n${response.status}\n${JSON.stringify(response.data)}`);
      } else {
        this.log(`Error trying to create user:\n${response.problem}\n${response.status}`);
      }
      return null;
    }

    const data = response.data as RegisterResponse;
    const token = data.token;
    this.refreshRequestHandler(token, nodeId, nodePublicKey);

    return data;
  }

  async createWallets(coinTypes: string[], verbose: boolean = false) {
    const response = await this.api.post<CreateMultipleWalletResponse>('/wallet/create_multiple', { coinTypes });

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to create wallet:\n', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to create wallet:\n', response.problem, response.status);
      }
      return null;
    }

    const wallet = (response.data as { walletList: CoinWallet[] }).walletList;

    return wallet;
  }

  async refreshToken(token: string, verbose: boolean = false) {
    const response = await this.api.post<LoginResponse>('/login/token', { token });

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to login with token', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to login with token', response.problem, response.status);
      }
      return null;
    }

    this.log('Refreshing token');
    const data = response.data as LoginResponse;
    const newToken = data.token;
    const user = data.user;
    const nodeId = user.nodeId;
    const nodePublicKey = user.nodePool.find(node => node.nodeId === nodeId)?.publicKey;

    this.refreshRequestHandler(newToken, nodeId, nodePublicKey || '');
    this.log('Refresh complete');

    return response.data;
  }

  async signMessage(message: string, coinType: string, verbose: boolean = false) {
    const response = await this.api.post('/transaction/sdk/signMessageSdk', { message, coinType });
    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to sign message', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to sign message', response.problem, response.status);
      }
      return null;
    }
    return response.data;
  }

  async signSerializedTx(serializedTx: string, coinType: string, verbose: boolean = false) {
    const response = await this.api.post('/transaction/sdk/signSerializedTxSdk', { serializedTx, coinType });
    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to sign serialized txxxxxxx', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to sign serialized tx', response.problem, response.status);
      }
      return null;
    }
    return response.data;
  }

  async verifySignature(coinType: string, message: string, signature: string, expectedAddress: string, verbose: boolean = false) {
    if (!SUPPORTED_COINS.includes(coinType)) {
      this.log('Invalid coin type');
      return null;
    }

    try {
      if (coinType === ETHEREUM) {
        const messageHash = hashMessage(message);
        const recoveredAddress = recoverAddress(messageHash, signature);

        const isValid = recoveredAddress?.toLowerCase() === expectedAddress?.toLowerCase();

        return isValid;
      }

      if (coinType === SOLANA) {
        const messageBytes = decodeUTF8(message);
        const signatureBytes = bs58.decode(signature);
        const addressBytes = bs58.decode(expectedAddress);

        this.log('Message Bytes:', Buffer.from(messageBytes).toString('hex'));
        this.log('Signature Bytes:', Buffer.from(signatureBytes).toString('hex'));
        this.log('Address Bytes:', Buffer.from(addressBytes).toString('hex'));

        const isVerified = nacl.sign.detached.verify(messageBytes, signatureBytes, addressBytes);
        return isVerified;
      }
    } catch (error) {
      if (verbose) {
        this.log('Error trying to check signature', error, JSON.stringify(error));
      } else {
        this.log('Error trying to check signature', error);
      }
      return null;
    }
  }

  async getNetworkStatus(verbose: boolean = false) {
    const response = await this.api.post<UserStatusResponse>('monitoring/userStatusV2');

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to retrieve network status', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to retrieve network status', response.problem, response.status);
      }
      return null;
    }
    return response.data;
  }

  async getNodes(verbose: boolean = false) {
    const data = await this.getNetworkStatus(verbose);
    if (!data) return null;

    const user = data.data.user;
    if (!user) return null; // sometimes user is not defined in the response

    const nodePool = data?.data.user?.nodePool;

    const types = {
      'userGuardian': 'userGuardian',
      'gridlockGuardian': 'gridlock',
      'ownerGuardian': 'owner',
      'partnerGuardian': 'partner',
    };

    const nodes = data.data.guardian.map(guardian => {
      return {
        nodeType: types[(nodePool.find(node => node.nodeId === guardian.nodeId)?.type as keyof typeof types) || ''],
        nodeId: guardian.nodeId,
        name: guardian.name,
        status: guardian.healthy ? 'Active' : 'Inactive',
        lastseen: guardian.lastseen,
      };
    });

    return nodes;
  }

  async getUser(verbose: boolean = false) {
    const response = await this.api.get<{ message: string; user?: User }>('/user');
    if (!response.ok || !response.data?.user) {
      if (verbose) {
        this.log('Error trying to get user', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to get user', response.problem, response.status);
      }
      return null;
    }

    return response.data.user as User;
  } 

  async getWallets(verbose: boolean = false) {
    const response = await this.api.get<{ message: string; wallets: CoinWallet[] }>('/wallet');

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to get user wallets', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to get user wallets', response.problem, response.status);
      }
      return null;
    }

    return response.data?.wallets as CoinWallet[];
  }

  async deleteUser(verbose: boolean = false) {
    const response = await this.api.delete('/user/safe');

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to delete user', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to delete user', response.problem, response.status);
      }
      return null;
    }

    return response.data;
  }

  async addUserGuardian(data: { name: string }, verbose: boolean = false) {
    const response = await this.api.post<Omit<ReplaceGuardianResponse, 'state'>>('user/guardian/add', data);

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to add guardian', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to add guardian', response.problem, response.status);
      }
      return null;
    }

    return response.data as Omit<ReplaceGuardianResponse, 'state'>;
  }

  async generateGuardianDeeplink(params: any, verbose: boolean = false) {
    const response = await this.api.post('/user/generateLink', { params });

    if (!response.ok) {
      if (verbose) {
        this.log('Error trying to generate link', response.problem, response.status, JSON.stringify(response.data));
      } else {
        this.log('Error trying to generate link', response.problem, response.status);
      }
      return null;
    }

    return response.data;
  }
}

export default GridlockSdk;
