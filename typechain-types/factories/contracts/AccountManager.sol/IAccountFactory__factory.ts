/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Interface, type ContractRunner } from "ethers";
import type {
  IAccountFactory,
  IAccountFactoryInterface,
} from "../../../contracts/AccountManager.sol/IAccountFactory";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "starterOwner",
        type: "address",
      },
      {
        internalType: "enum WalletType",
        name: "walletType",
        type: "uint8",
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
    name: "clone",
    outputs: [
      {
        internalType: "contract Account",
        name: "acct",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

export class IAccountFactory__factory {
  static readonly abi = _abi;
  static createInterface(): IAccountFactoryInterface {
    return new Interface(_abi) as IAccountFactoryInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): IAccountFactory {
    return new Contract(address, _abi, runner) as unknown as IAccountFactory;
  }
}
