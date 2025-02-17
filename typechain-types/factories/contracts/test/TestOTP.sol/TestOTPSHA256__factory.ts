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
import type { NonPayableOverrides } from "../../../../common";
import type {
  TestOTPSHA256,
  TestOTPSHA256Interface,
} from "../../../../contracts/test/TestOTP.sol/TestOTPSHA256";

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes",
        name: "key",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "message",
        type: "bytes",
      },
    ],
    name: "HMAC",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "K",
        type: "bytes",
      },
      {
        internalType: "uint64",
        name: "C",
        type: "uint64",
      },
    ],
    name: "HOTP",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "key",
        type: "bytes",
      },
      {
        internalType: "uint32",
        name: "time_step",
        type: "uint32",
      },
      {
        internalType: "uint32",
        name: "when",
        type: "uint32",
      },
    ],
    name: "TOTP",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60808060405234610016576105b8908161001c8239f35b600080fdfe6040608081526004908136101561001557600080fd5b6000803560e01c806343501d60146101285780636cd87a9c146100ca5763e5373c951461004157600080fd5b346100c35760603660031901126100c357823567ffffffffffffffff81116100c65761007090369085016101aa565b9060243563ffffffff918282168092036100c357604435908382168092036100c35782156100b0576020866100a9858504871688610206565b9051908152f35b634e487b7160e01b815260128752602490fd5b80fd5b5080fd5b50913461012457816003193601126101245767ffffffffffffffff8135818111610120576100fb90369084016101aa565b936024359182116100c357509261011a6100a9926020953691016101aa565b90610358565b8480fd5b8280fd5b50346100c357816003193601126100c35767ffffffffffffffff92803584811161012457610158913691016101aa565b9060243593841684036100c357506020926100a991610206565b90601f8019910116810190811067ffffffffffffffff82111761019457604052565b634e487b7160e01b600052604160045260246000fd5b81601f820112156102015780359067ffffffffffffffff821161019457604051926101df601f8401601f191660200185610172565b8284526020838301011161020157816000926020809301838601378301015290565b600080fd5b6040805160c09390931b6001600160c01b0319166020840152600883528201919067ffffffffffffffff8311828410176101945761024692604052610358565b600f811660208110156102bf5760ff90600181018281116102d55782169060208210156102bf57600281018381116102d55783169260208410156102bf57600382018181116102d5571660208110156102bf57848080620f424097637f000000941a961a60081b941a60101b921a60181b161717170690565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60001981146102d55760010190565b9081518110156102bf570160200190565b818102929181159184041417156102d557565b60ff81116102d5576001901b90565b9081519160005b838110610345575050016000815290565b8060208092840101518185015201610334565b60009182916040938482511160001461049e5750600061037f60209286519182809261032d565b039060025afa1561049357600051915b602060006104158361040a7f5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c966103fc7f3636363636363636363636363636363636363636363636363636363636363636918b5194838c8795188a860152188c840152606083019061032d565b03601f198101835282610172565b87519182809261032d565b039060025afa156104885760005191845193811860208501521883830152606082015260608152608081019080821067ffffffffffffffff83111761019457818352602091600091607f199061046b838261032d565b03019060025afa1561047e575060005190565b513d6000823e3d90fd5b83513d6000823e3d90fd5b82513d6000823e3d90fd5b9490929190855b8451871080610578575b15610505576104be87866102fa565b5160f81c90601f8881039081116102d5576001600160fd1b03811681036102d5576104ff926104f26104f89260031b61031e565b9061030b565b17966102eb565b956104a5565b909295509390936020955b845187108061056f575b156105635761052987866102fa565b5160f81c90603f8881039081116102d5576001600160fd1b03811681036102d55761055d926104f26104f89260031b61031e565b95610510565b9194929550925061038f565b5082871061051a565b50602087106104af56fea26469706673582212208f5f2b6dd036bb71a72a0a37a7b0b0aaf56fe82db7752433fca86d3c37811e1564736f6c63430008160033";

type TestOTPSHA256ConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: TestOTPSHA256ConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class TestOTPSHA256__factory extends ContractFactory {
  constructor(...args: TestOTPSHA256ConstructorParams) {
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
      TestOTPSHA256 & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): TestOTPSHA256__factory {
    return super.connect(runner) as TestOTPSHA256__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TestOTPSHA256Interface {
    return new Interface(_abi) as TestOTPSHA256Interface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): TestOTPSHA256 {
    return new Contract(address, _abi, runner) as unknown as TestOTPSHA256;
  }
}
