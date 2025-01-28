/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Interface, type ContractRunner } from "ethers";
import type {
  IAccount,
  IAccountInterface,
} from "../../../contracts/AccountManager.sol/IAccount";

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "keypairSecret",
        type: "bytes32",
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
] as const;

export class IAccount__factory {
  static readonly abi = _abi;
  static createInterface(): IAccountInterface {
    return new Interface(_abi) as IAccountInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): IAccount {
    return new Contract(address, _abi, runner) as unknown as IAccount;
  }
}
