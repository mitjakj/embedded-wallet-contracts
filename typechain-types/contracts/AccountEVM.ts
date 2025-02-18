/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumberish,
  BytesLike,
  FunctionFragment,
  Result,
  Interface,
  EventFragment,
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedLogDescription,
  TypedListener,
  TypedContractMethod,
} from "../common";

export type SignatureRSVStruct = {
  r: BytesLike;
  s: BytesLike;
  v: BigNumberish;
};

export type SignatureRSVStructOutput = [r: string, s: string, v: bigint] & {
  r: string;
  s: string;
  v: bigint;
};

export declare namespace EIP155Signer {
  export type EthTxStruct = {
    nonce: BigNumberish;
    gasPrice: BigNumberish;
    gasLimit: BigNumberish;
    to: AddressLike;
    value: BigNumberish;
    data: BytesLike;
    chainId: BigNumberish;
  };

  export type EthTxStructOutput = [
    nonce: bigint,
    gasPrice: bigint,
    gasLimit: bigint,
    to: string,
    value: bigint,
    data: string,
    chainId: bigint
  ] & {
    nonce: bigint;
    gasPrice: bigint;
    gasLimit: bigint;
    to: string;
    value: bigint;
    data: string;
    chainId: bigint;
  };
}

export interface AccountEVMInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "addressToBytes32"
      | "bytes32ToAddress"
      | "call"
      | "createWallet"
      | "exportPrivateKey"
      | "getWalletList"
      | "init"
      | "isController"
      | "modifyController"
      | "removeWallet"
      | "sign"
      | "signEIP155"
      | "staticcall"
      | "transfer"
      | "walletAddress"
  ): FunctionFragment;

  getEvent(nameOrSignatureOrTopic: "WalletCreate"): EventFragment;

  encodeFunctionData(
    functionFragment: "addressToBytes32",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "bytes32ToAddress",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "call",
    values: [AddressLike, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "createWallet",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "exportPrivateKey",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "getWalletList",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "init",
    values: [AddressLike, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "isController",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "modifyController",
    values: [AddressLike, boolean]
  ): string;
  encodeFunctionData(
    functionFragment: "removeWallet",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "sign",
    values: [BigNumberish, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "signEIP155",
    values: [BigNumberish, EIP155Signer.EthTxStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "staticcall",
    values: [AddressLike, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "transfer",
    values: [AddressLike, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "walletAddress",
    values: [BigNumberish]
  ): string;

  decodeFunctionResult(
    functionFragment: "addressToBytes32",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "bytes32ToAddress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "call", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "createWallet",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "exportPrivateKey",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getWalletList",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "init", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "isController",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "modifyController",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "removeWallet",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "sign", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "signEIP155", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "staticcall", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "transfer", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "walletAddress",
    data: BytesLike
  ): Result;
}

export namespace WalletCreateEvent {
  export type InputTuple = [publicAddress: BytesLike];
  export type OutputTuple = [publicAddress: string];
  export interface OutputObject {
    publicAddress: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface AccountEVM extends BaseContract {
  connect(runner?: ContractRunner | null): AccountEVM;
  waitForDeployment(): Promise<this>;

  interface: AccountEVMInterface;

  queryFilter<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;
  queryFilter<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;

  on<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  on<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  once<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  once<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  listeners<TCEvent extends TypedContractEvent>(
    event: TCEvent
  ): Promise<Array<TypedListener<TCEvent>>>;
  listeners(eventName?: string): Promise<Array<Listener>>;
  removeAllListeners<TCEvent extends TypedContractEvent>(
    event?: TCEvent
  ): Promise<this>;

  addressToBytes32: TypedContractMethod<[_addr: AddressLike], [string], "view">;

  bytes32ToAddress: TypedContractMethod<[_b: BytesLike], [string], "view">;

  call: TypedContractMethod<
    [in_contract: AddressLike, in_data: BytesLike],
    [string],
    "nonpayable"
  >;

  createWallet: TypedContractMethod<
    [keypairSecret: BytesLike],
    [string],
    "nonpayable"
  >;

  exportPrivateKey: TypedContractMethod<
    [walletId: BigNumberish],
    [string],
    "view"
  >;

  getWalletList: TypedContractMethod<[], [string[]], "view">;

  init: TypedContractMethod<
    [initialController: AddressLike, keypairSecret: BytesLike],
    [void],
    "nonpayable"
  >;

  isController: TypedContractMethod<[who: AddressLike], [boolean], "view">;

  modifyController: TypedContractMethod<
    [who: AddressLike, status: boolean],
    [void],
    "nonpayable"
  >;

  removeWallet: TypedContractMethod<
    [walletId: BigNumberish],
    [void],
    "nonpayable"
  >;

  sign: TypedContractMethod<
    [walletId: BigNumberish, digest: BytesLike],
    [SignatureRSVStructOutput],
    "view"
  >;

  signEIP155: TypedContractMethod<
    [walletId: BigNumberish, txToSign: EIP155Signer.EthTxStruct],
    [string],
    "view"
  >;

  staticcall: TypedContractMethod<
    [in_contract: AddressLike, in_data: BytesLike],
    [string],
    "view"
  >;

  transfer: TypedContractMethod<
    [in_target: AddressLike, amount: BigNumberish],
    [void],
    "nonpayable"
  >;

  walletAddress: TypedContractMethod<
    [walletId: BigNumberish],
    [string],
    "view"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "addressToBytes32"
  ): TypedContractMethod<[_addr: AddressLike], [string], "view">;
  getFunction(
    nameOrSignature: "bytes32ToAddress"
  ): TypedContractMethod<[_b: BytesLike], [string], "view">;
  getFunction(
    nameOrSignature: "call"
  ): TypedContractMethod<
    [in_contract: AddressLike, in_data: BytesLike],
    [string],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "createWallet"
  ): TypedContractMethod<[keypairSecret: BytesLike], [string], "nonpayable">;
  getFunction(
    nameOrSignature: "exportPrivateKey"
  ): TypedContractMethod<[walletId: BigNumberish], [string], "view">;
  getFunction(
    nameOrSignature: "getWalletList"
  ): TypedContractMethod<[], [string[]], "view">;
  getFunction(
    nameOrSignature: "init"
  ): TypedContractMethod<
    [initialController: AddressLike, keypairSecret: BytesLike],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "isController"
  ): TypedContractMethod<[who: AddressLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "modifyController"
  ): TypedContractMethod<
    [who: AddressLike, status: boolean],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "removeWallet"
  ): TypedContractMethod<[walletId: BigNumberish], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "sign"
  ): TypedContractMethod<
    [walletId: BigNumberish, digest: BytesLike],
    [SignatureRSVStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "signEIP155"
  ): TypedContractMethod<
    [walletId: BigNumberish, txToSign: EIP155Signer.EthTxStruct],
    [string],
    "view"
  >;
  getFunction(
    nameOrSignature: "staticcall"
  ): TypedContractMethod<
    [in_contract: AddressLike, in_data: BytesLike],
    [string],
    "view"
  >;
  getFunction(
    nameOrSignature: "transfer"
  ): TypedContractMethod<
    [in_target: AddressLike, amount: BigNumberish],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "walletAddress"
  ): TypedContractMethod<[walletId: BigNumberish], [string], "view">;

  getEvent(
    key: "WalletCreate"
  ): TypedContractEvent<
    WalletCreateEvent.InputTuple,
    WalletCreateEvent.OutputTuple,
    WalletCreateEvent.OutputObject
  >;

  filters: {
    "WalletCreate(bytes32)": TypedContractEvent<
      WalletCreateEvent.InputTuple,
      WalletCreateEvent.OutputTuple,
      WalletCreateEvent.OutputObject
    >;
    WalletCreate: TypedContractEvent<
      WalletCreateEvent.InputTuple,
      WalletCreateEvent.OutputTuple,
      WalletCreateEvent.OutputObject
    >;
  };
}
