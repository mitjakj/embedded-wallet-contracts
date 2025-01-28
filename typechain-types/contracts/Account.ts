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
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedListener,
  TypedContractMethod,
} from "../common";

export interface AccountInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "call"
      | "createWallet"
      | "exportPrivateKey"
      | "getWalletList"
      | "init"
      | "isController"
      | "modifyController"
      | "staticcall"
      | "transfer"
      | "walletAddress"
  ): FunctionFragment;

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
  decodeFunctionResult(functionFragment: "staticcall", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "transfer", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "walletAddress",
    data: BytesLike
  ): Result;
}

export interface Account extends BaseContract {
  connect(runner?: ContractRunner | null): Account;
  waitForDeployment(): Promise<this>;

  interface: AccountInterface;

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

  filters: {};
}
