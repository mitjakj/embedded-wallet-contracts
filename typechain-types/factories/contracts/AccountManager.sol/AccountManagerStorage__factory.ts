/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type { Signer, ContractDeployTransaction, ContractRunner } from "ethers";
import type { NonPayableOverrides } from "../../../common";
import type {
  AccountManagerStorage,
  AccountManagerStorageInterface,
} from "../../../contracts/AccountManager.sol/AccountManagerStorage";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "dataHash",
        type: "bytes32",
      },
      {
        indexed: true,
        internalType: "bytes32",
        name: "hashedUsername",
        type: "bytes32",
      },
      {
        indexed: true,
        internalType: "address",
        name: "publicAddress",
        type: "address",
      },
    ],
    name: "GaslessTransaction",
    type: "event",
  },
  {
    inputs: [],
    name: "gaspayingAddress",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "hashUsage",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "personalization",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "salt",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "signer",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

const _bytecode =
  "0x6080806040523461001657610148908161001c8239f35b600080fdfe60806040818152600436101561001457600080fd5b600091823560e01c908163108a5eee146100ed57508063238ac933146100c5578063bfa0b133146100a7578063f9f910af1461007a5763fd24dc1e1461005957600080fd5b346100765781600319360112610076576020906006549051908152f35b5080fd5b50346100765760203660031901126100765760ff816020936004358152600a855220541690519015158152f35b50346100765781600319360112610076576020906004549051908152f35b503461007657816003193601126100765760095490516001600160a01b039091168152602090f35b8390346100765781600319360112610076576007546001600160a01b03168152602090f3fea26469706673582212203e5804995151aecfbd62feb0f6b54c1ddd7fb537953829b29c8571a9ff00d14e64736f6c63430008150033";

type AccountManagerStorageConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AccountManagerStorageConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class AccountManagerStorage__factory extends ContractFactory {
  constructor(...args: AccountManagerStorageConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(overrides || {});
  }
  override deploy(overrides?: NonPayableOverrides & { from?: string }) {
    return super.deploy(overrides || {}) as Promise<
      AccountManagerStorage & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): AccountManagerStorage__factory {
    return super.connect(runner) as AccountManagerStorage__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AccountManagerStorageInterface {
    return new Interface(_abi) as AccountManagerStorageInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): AccountManagerStorage {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as AccountManagerStorage;
  }
}
