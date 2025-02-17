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
  TestHelper,
  TestHelperInterface,
} from "../../../contracts/test/TestHelper";

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes",
        name: "in_data",
        type: "bytes",
      },
      {
        internalType: "bytes32",
        name: "personalization",
        type: "bytes32",
      },
    ],
    name: "createChallengeBase64",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "authenticatorData",
        type: "bytes",
      },
      {
        components: [
          {
            internalType: "enum MakeJSON.ValueType",
            name: "t",
            type: "uint8",
          },
          {
            internalType: "string",
            name: "k",
            type: "string",
          },
          {
            internalType: "string",
            name: "v",
            type: "string",
          },
        ],
        internalType: "struct MakeJSON.KeyValue[]",
        name: "clientDataTokens",
        type: "tuple[]",
      },
    ],
    name: "createDigest",
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
] as const;

const _bytecode =
  "0x60808060405234610016576109bc908161001c8239f35b600080fdfe6080604052600436101561001257600080fd5b6000803560e01c90816320ab2eab1461003a57506391b22db51461003557600080fd5b61014f565b346100c65760403660031901126100c65767ffffffffffffffff906004358281116100c95761006d9036906004016100cd565b9091602435908482116100c657366023830112156100c65781600401359485116100c6573660248660051b840101116100c6576100c26100b286602485018688610327565b6040519081529081906020820190565b0390f35b80fd5b5080fd5b9181601f840112156100fb5782359167ffffffffffffffff83116100fb57602083818601950101116100fb57565b600080fd5b60005b8381106101135750506000910152565b8181015183820152602001610103565b604091602082526101438151809281602086015260208686019101610100565b601f01601f1916010190565b346100fb576040806003193601126100fb5760043567ffffffffffffffff81116100fb57600061018560209236906004016100cd565b9081855192839283378101838152039060025afa1561021757602060006101cc815184519060243585830152858201528481526101c181610232565b8451918280926102f4565b039060025afa15610217576100c29061020c6101f961020760005184519283916020830160209181520190565b03601f19810183528261026f565b61058f565b905191829182610123565b61030b565b634e487b7160e01b600052604160045260246000fd5b6060810190811067ffffffffffffffff82111761024e57604052565b61021c565b6040810190811067ffffffffffffffff82111761024e57604052565b90601f8019910116810190811067ffffffffffffffff82111761024e57604052565b67ffffffffffffffff811161024e57601f01601f191660200190565b81601f820112156100fb578035906102c482610291565b926102d2604051948561026f565b828452602083830101116100fb57816000926020809301838601378301015290565b9061030760209282815194859201610100565b0190565b6040513d6000823e3d90fd5b8260209493928237019081520190565b919267ffffffffffffffff9081811161024e578060051b946020956040938451936103548984018661026f565b8452878401918301923684116100fb579081899594935b8484106103fc5750505050509060006103ae61038c8261039a97969561074c565b8451968791858301906102f4565b03956101c1601f199788810183528261026f565b039060025afa15610217576103e16103eb936000956103d5875185519687938b8501610317565b0390810184528361026f565b51918280926102f4565b039060025afa156102175760005190565b9091928094959650358381116100fb5782016060813603126100fb5787519161042483610232565b813560028110156100fb5783528b8201358581116100fb5761044990369084016102ad565b8c84015288820135928584116100fb576104698d949385943691016102ad565b8a820152815201930191908995949361036b565b604051906020820182811067ffffffffffffffff82111761024e5760405260008252565b604051906104ae82610232565b604082527f6768696a6b6c6d6e6f707172737475767778797a303132333435363738392d5f6040837f4142434445464748494a4b4c4d4e4f505152535455565758595a61626364656660208201520152565b634e487b7160e01b600052601160045260246000fd5b906002820180921161052457565b610500565b906020820180921161052457565b906001820180921161052457565b600281901b91906001600160fe1b0381160361052457565b9061056782610291565b610574604051918261026f565b8281528092610585601f1991610291565b0190602036910137565b8051156106605761059e6104a1565b906105bb6105b66105af8351610516565b6003900490565b610545565b916105cd6105c884610529565b61055d565b928352818251830191602085015b8383106106145750505050600390510680600114610608576002146105fd5790565b805160001901815290565b50805160011901815290565b6004906003809401938451600190603f9082828260121c16880101518553828282600c1c16880101518386015382828260061c16880101516002860153168501015190820153016105db565b5061066961047d565b90565b80518210156106805760209160051b010190565b634e487b7160e01b600052603260045260246000fd5b60001981019190821161052457565b604051906106b282610253565b60018252607d60f81b6020830152565b600211156106cc57565b634e487b7160e01b600052602160045260246000fd5b6040516020810190637472756560e01b82526004815261070181610253565b51902090565b60405162461bcd60e51b815260206004820152601b60248201527f4d616b654a534f4e2e56616c7565547970652e756e6b6e6f776e2100000000006044820152606490fd5b90610757818361066c565b51916107638151610696565b820361096d57506107726106a5565b905b825161077f816106c2565b610788816106c2565b61082757156107ed57816101f9610669926107cb6107e0604060206107d19801519501516107cb6040519889976107cb60208a0160029061161160f11b81520190565b906102f4565b62111d1160e91b815260030190565b601160f91b815260010190565b816101f9610669926107cb6107e0604060206107d19801519501516107cb6040519889976107cb60208a01600290613d9160f11b81520190565b919060018251610836816106c2565b61083f816106c2565b0361070757604080830151928151946020948661085f87820180936102f4565b0396610873601f199889810183528261026f565b51902061087e6106e2565b1490610911576108d3578301519051613d9160f11b9381019384529361066993909285926108c7926107cb916108b49160020183565b66223a66616c736560c81b815260070190565b0390810183528261026f565b8301519051613d9160f11b9381019384529361066993909285926108c7926107cb916108ff9160020183565b65223a7472756560d01b815260060190565b61094157830151905161161160f11b9381019384529361066993909285926108c7926107cb916108b49160020183565b830151905161161160f11b9381019384529361066993909285926108c7926107cb916108ff9160020183565b6109809061097a83610537565b9061074c565b9061077456fea2646970667358221220dfb00440b37b746e4457ddeb6c81a2c64588389fa500c4573ba69635a106e31b64736f6c63430008160033";

type TestHelperConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: TestHelperConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class TestHelper__factory extends ContractFactory {
  constructor(...args: TestHelperConstructorParams) {
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
      TestHelper & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): TestHelper__factory {
    return super.connect(runner) as TestHelper__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TestHelperInterface {
    return new Interface(_abi) as TestHelperInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): TestHelper {
    return new Contract(address, _abi, runner) as unknown as TestHelper;
  }
}
