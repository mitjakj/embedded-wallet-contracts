/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Interface, type ContractRunner } from "ethers";
import type { Account, AccountInterface } from "../../contracts/Account";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "in_contract",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "in_data",
        type: "bytes",
      },
    ],
    name: "call",
    outputs: [
      {
        internalType: "bytes",
        name: "out_data",
        type: "bytes",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "keypairSecret",
        type: "bytes32",
      },
      {
        internalType: "string",
        name: "title",
        type: "string",
      },
    ],
    name: "createWallet",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "walletId",
        type: "uint256",
      },
    ],
    name: "exportPrivateKey",
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
    name: "getWalletList",
    outputs: [
      {
        components: [
          {
            internalType: "address",
            name: "keypairAddress",
            type: "address",
          },
          {
            internalType: "string",
            name: "title",
            type: "string",
          },
        ],
        internalType: "struct Wallet[]",
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "starterOwner",
        type: "address",
      },
      {
        internalType: "bytes32",
        name: "keypairSecret",
        type: "bytes32",
      },
      {
        internalType: "string",
        name: "title",
        type: "string",
      },
    ],
    name: "init",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "who",
        type: "address",
      },
    ],
    name: "isController",
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
    inputs: [
      {
        internalType: "address",
        name: "who",
        type: "address",
      },
      {
        internalType: "bool",
        name: "status",
        type: "bool",
      },
    ],
    name: "modifyController",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "in_contract",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "in_data",
        type: "bytes",
      },
    ],
    name: "staticcall",
    outputs: [
      {
        internalType: "bytes",
        name: "out_data",
        type: "bytes",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "in_target",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "transfer",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "walletId",
        type: "uint256",
      },
      {
        internalType: "string",
        name: "title",
        type: "string",
      },
    ],
    name: "updateTitle",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "walletId",
        type: "uint256",
      },
    ],
    name: "walletAddress",
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

export class Account__factory {
  static readonly abi = _abi;
  static createInterface(): AccountInterface {
    return new Interface(_abi) as AccountInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): Account {
    return new Contract(address, _abi, runner) as unknown as Account;
  }
}
