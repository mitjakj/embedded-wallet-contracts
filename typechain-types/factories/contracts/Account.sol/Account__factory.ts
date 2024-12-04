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
  Account,
  AccountInterface,
} from "../../../contracts/Account.sol/Account";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [],
    name: "DER_Split_Error",
    type: "error",
  },
  {
    inputs: [],
    name: "expmod_Error",
    type: "error",
  },
  {
    inputs: [],
    name: "k256Decompress_Invalid_Length_Error",
    type: "error",
  },
  {
    inputs: [],
    name: "k256DeriveY_Invalid_Prefix_Error",
    type: "error",
  },
  {
    inputs: [],
    name: "recoverV_Error",
    type: "error",
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
            internalType: "enum WalletType",
            name: "walletType",
            type: "uint8",
          },
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
        internalType: "uint256",
        name: "walletId",
        type: "uint256",
      },
      {
        internalType: "bytes32",
        name: "digest",
        type: "bytes32",
      },
    ],
    name: "sign",
    outputs: [
      {
        components: [
          {
            internalType: "bytes32",
            name: "r",
            type: "bytes32",
          },
          {
            internalType: "bytes32",
            name: "s",
            type: "bytes32",
          },
          {
            internalType: "uint256",
            name: "v",
            type: "uint256",
          },
        ],
        internalType: "struct SignatureRSV",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
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
        components: [
          {
            internalType: "uint64",
            name: "nonce",
            type: "uint64",
          },
          {
            internalType: "uint256",
            name: "gasPrice",
            type: "uint256",
          },
          {
            internalType: "uint64",
            name: "gasLimit",
            type: "uint64",
          },
          {
            internalType: "address",
            name: "to",
            type: "address",
          },
          {
            internalType: "uint256",
            name: "value",
            type: "uint256",
          },
          {
            internalType: "bytes",
            name: "data",
            type: "bytes",
          },
          {
            internalType: "uint256",
            name: "chainId",
            type: "uint256",
          },
        ],
        internalType: "struct EIP155Signer.EthTx",
        name: "txToSign",
        type: "tuple",
      },
    ],
    name: "signEIP155",
    outputs: [
      {
        internalType: "bytes",
        name: "",
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

const _bytecode =
  "0x6080806040523461002357600160ff19600054161760005561228b90816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146100e75780631b8b921d146100e2578063260558a0146100dd57806337022e98146100d85780635786ead2146100d35780635b06fdc8146100ce5780637d1f3b6f146100c957806388196f68146100c4578063a9059cbb146100bf578063b429afeb146100ba578063becd532d146100b5578063e341eaa4146100b05763fc9ffe02146100ab57600080fd5b610b3e565b6109ca565b610944565b610905565b610898565b610849565b6107d0565b610704565b610578565b6103e9565b6103a0565b61032e565b610148565b60005b8381106100ff5750506000910152565b81810151838201526020016100ef565b90602091610128815180928185528580860191016100ec565b601f01601f1916010190565b90602061014592818152019061010f565b90565b346102a3576003196040368201126102a357600435906024356001600160401b03918282116102a35760e09082360301126102a3576101bb6101b560009433865260016020526101a3600160ff604089205416151514610be7565b6101b06002548210610c26565b610c7c565b50610d01565b60208101805191516001600160a01b039283169392909190600383101561029e5761020492875260036020526040872091511660018060a01b0316600052602052604060002090565b549261020e6104fa565b9461021b83600401610dfb565b86526024830135602087015261023360448401610dfb565b6040870152610244606484016102be565b60608701526084830135608087015260a483013591821161029b5761029761028b87878760c48861027a368a8301600401610531565b60a0860152013560c0840152610eea565b60405191829182610134565b0390f35b80fd5b610a8a565b600080fd5b600435906001600160a01b03821682036102a357565b35906001600160a01b03821682036102a357565b60406003198201126102a3576004356001600160a01b03811681036102a357916024356001600160401b03928382116102a357806023830112156102a35781600401359384116102a357602484830101116102a3576024019190565b346102a35761033c366102d2565b916000928380933382526001602052610360600160ff604085205416151514610be7565b826040519384928337810182815203925af161037a611bc6565b9015610398576102979060405191829160208352602083019061010f565b602081519101fd5b346102a3576000806103b1366102d2565b9033845260016020526103cf600160ff604087205416151514610be7565b816040519283928337810184815203915afa61037a611bc6565b346102a35760403660031901126102a3576104026102a8565b6024358015158091036102a357600091338352600160205261042f600160ff604086205416151514610be7565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b0382111761048357604052565b610452565b60e081019081106001600160401b0382111761048357604052565b604081019081106001600160401b0382111761048357604052565b602081019081106001600160401b0382111761048357604052565b90601f801991011681019081106001600160401b0382111761048357604052565b6040519061050782610488565b565b6040519061050782610468565b6001600160401b03811161048357601f01601f191660200190565b81601f820112156102a35780359061054882610516565b9261055660405194856104d9565b828452602083830101116102a357816000926020809301838601378301015290565b346102a35760403660031901126102a3576001600160401b036004356024358281116102a3576105ac903690600401610531565b6000923384526001926020908482526105cf8560ff604089205416151514610be7565b6105dc6002548210610c26565b8351156106b8576105ed8591610c7c565b50019383519283116104835761060d836106078754610cc7565b87611bf6565b81601f841160011461064d575050819061063d938692610642575b50508160011b916000199060031b1c19161790565b905580f35b015190503880610628565b91909383601f19811661066588600052602060002090565b9489905b8883831061069e5750505010610685575b505050811b01905580f35b015160001960f88460031b161c1916905538808061067a565b858701518855909601959485019487935090810190610669565b60405162461bcd60e51b81526004810183905260156024820152745469746c652063616e6e6f7420626520656d70747960581b6044820152606490fd5b6024359060038210156102a357565b346102a35760803660031901126102a35761071d6102a8565b6107256106f5565b6064356001600160401b0381116102a357610744903690600401610531565b9060ff60005416610796576107819260018060a01b031660005260016020526107786040600020600160ff19825416179055565b60443590611e37565b50610794600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b346102a35760203660031901126102a357336000526001602052610800600160ff60406000205416151514610be7565b61080e6101b5600435610c7c565b8051600381101561029e576000908152600360209081526040808320938201516001600160a01b031683529281529082902054915191825290f35b346102a35760203660031901126102a357602061088060043533600052600183526101a3600160ff60406000205416151514610be7565b505460405160089190911c6001600160a01b03168152f35b346102a35760403660031901126102a3576108b16102a8565b60243590600080808094819433835260016020526108da600160ff604086205416151514610be7565b829082156108fb575b6001600160a01b031690f1156108f65780f35b611598565b6108fc91506108e3565b346102a35760203660031901126102a3576001600160a01b036109266102a8565b166000526001602052602060ff604060002054166040519015158152f35b346102a35760603660031901126102a35760043560038110156102a3576044356001600160401b0381116102a357610297916109876109b0923690600401610531565b903360005260016020526109a7600160ff60406000205416151514610be7565b60243590611e37565b6040516001600160a01b0390911681529081906020820190565b346102a35760403660031901126102a357610a0c6101b56004356109ec611203565b503360005260016020526101a3600160ff60406000205416151514610be7565b6020810180519151916001600160a01b0391908216600384101561029e57610a5f610a669361029795600052600360205260406000209060243594511660018060a01b0316600052602052604060002090565b5490611239565b60408051825181526020808401519082015291810151908201529081906060820190565b634e487b7160e01b600052602160045260246000fd5b6003111561029e57565b60208082019080835283518092526040928381019382818560051b8401019601946000925b858410610ae0575050505050505090565b90919293949596603f198282030183528751606090805190600382101561029e5783899388610b2d93869560019852878060a01b03868201511686850152015191818a820152019061010f565b990193019401929195949390610acf565b346102a35760008060031936011261029b57338152600190602090828252610b708360ff604084205416151514610be7565b6002805491610b7e83610f9e565b93610b8c60405195866104d9565b8385528282527f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace8186015b858410610bcc57604051806102978982610aaa565b84838992610bd985610d01565b815201920193019290610bb7565b15610bee57565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b15610c2d57565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b600254811015610cb657600260005260011b7f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace0190600090565b610c66565b600382101561029e5752565b90600182811c92168015610cf7575b6020831014610ce157565b634e487b7160e01b600052602260045260246000fd5b91607f1691610cd6565b9060405191610d0f83610468565b82815491610d2060ff841683610cbb565b60209260018060a01b039060081c1683830152600180910190604051938492600092815491610d4e83610cc7565b80875292828116908115610dc15750600114610d7c575b5050505060409291610d789103846104d9565b0152565b60009081528381209695945091905b818310610da957509394509192509082010181610d78604038610d65565b86548884018501529586019587945091830191610d8b565b60ff191685880152505050151560051b830101905081610d78604038610d65565b600381101561029e576000526003602052604060002090565b35906001600160401b03821682036102a357565b634e487b7160e01b600052601160045260246000fd5b600019810191908211610e3457565b610e0f565b6020039060208211610e3457565b6401000003d01990810391908211610e3457565b91908203918211610e3457565b600381901b91906001600160fd1b03811603610e3457565b908160081b918083046101001490151715610e3457565b9060238201809211610e3457565b6004019081600411610e3457565b9060018201809211610e3457565b9060048201809211610e3457565b9060028201809211610e3457565b91908201809211610e3457565b610f5a90929192610ef9611203565b5060c0830193610f27855160405190610f1182610468565b600082526000602083015260408201528561109c565b604051610f5160208281610f4481830196878151938492016100ec565b81010380845201826104d9565b51902091611239565b9060408201805193601a198501948511610e3457518060011b9080820460021490151715610e3457610f92610f979161014596610edd565b610e97565b905261109c565b6001600160401b0381116104835760051b60200190565b6040519061014082018281106001600160401b0382111761048357604052600982528160005b6101208110610fe8575050565b806060602080938501015201610fdb565b805115610cb65760200190565b805160011015610cb65760400190565b805160021015610cb65760600190565b805160031015610cb65760800190565b805160041015610cb65760a00190565b805160051015610cb65760c00190565b805160061015610cb65760e00190565b805160071015610cb6576101000190565b805160081015610cb6576101200190565b8051821015610cb65760209160051b010190565b6111ea60206101459361119060a06110b2610fb5565b956110db6110d66110ca83516001600160401b031690565b6001600160401b031690565b611950565b6110e488610ff9565b526110ee87610ff9565b506110fb85820151611950565b61110488611006565b5261110e87611006565b506111296110d66110ca60408401516001600160401b031690565b61113288611016565b5261113c87611016565b506060810151611154906001600160a01b031661191e565b61115d88611026565b5261116787611026565b506111756080820151611950565b61117e88611036565b5261118887611036565b50015161167f565b61119985611046565b526111a384611046565b506111b16040820151611950565b6111ba85611056565b526111c484611056565b506111cf8151611950565b6111d885611066565b526111e284611066565b500151611950565b6111f382611077565b526111fd81611077565b506117fb565b6040519061121082610468565b60006040838281528260208201520152565b90611235602092828151948592016100ec565b0190565b90929192611245611203565b50604090600080836112b26112e1825160209687820152868152611268816104a3565b8351908b8883015287825261127c826104a3565b6112d5855161128a816104be565b8781526112c5875196879460808d87019a6112a58c60049052565b87015260a086019061010f565b601f19958686830301606087015261010f565b908484830301608085015261010f565b039081018352826104d9565b51906006600160981b015afa916112f6611bc6565b92156113135750509061130b61050792611396565b9384916115a4565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b805160021015610cb65760220190565b805160011015610cb65760210190565b805160031015610cb65760230190565b805160041015610cb65760240190565b908151811015610cb6570160200190565b9061139f611203565b916008815110611551576001600160f81b0319600360fc1b816113d26113c485610ff9565b516001600160f81b03191690565b160361155157600160f91b80826113eb6113c486611345565b16036115515761140f6114096114036113c486611355565b60f81c90565b60ff1690565b916114226114096114036113c487611365565b92602184116115515761143484610ea5565b906114506114096114036113c461144a86610eb3565b8a611385565b9360218511611551576114766114696113c4858a611385565b6001600160f81b03191690565b03611551578061148e6114898688610edd565b610ec1565b036115515761149e865191610ecf565b03611551576114ac90610ecf565b9060049060218514611563575b6021841461151e575b50906020809286010151940101519160208110611507575b50602081106114ef575b509083526020830152565b6114fb61150091610e39565b610e68565b1c386114e4565b6114fb61151691949294610e39565b1c91386114da565b61152e6113c48488969496611385565b166115515760206115486115428294610eb3565b92610e25565b939192506114c2565b6040516386cd05c560e01b8152600490fd5b9390846115726113c488611375565b166115895750611583600591610e25565b936114b9565b6040516386cd05c560e01b8152fd5b6040513d6000823e3d90fd5b916040810190601b8252805192602082019060206115e0835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa156108f65784516001600160a01b039687169616869003611613575b505050505050565b6116458593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa156108f657516001600160a01b03160361166d5738808080808061160b565b604051634532600d60e01b8152600490fd5b9060009180519260019384811490816117e3575b501561169e57509150565b8151936038851015611710575092611702610145926116fc94956116df6116cf60ff6116c8611a23565b9616611a99565b60f81b6001600160f81b03191690565b901a6116ea84610ff9565b535b6040519485936020850190611222565b90611222565b03601f1981018352826104d9565b9190808380805b6117b1575b505061172f61172a83610eb3565b611a55565b936117476116cf61174260ff8616611a99565b611a87565b821a61175286610ff9565b535b82811115611772575050506116fc92935090611702610145926116ec565b8061179a6116cf61140961140961179461178f6117ac978a610e5b565b611abd565b8c6119f4565b831a6117a68288611385565b53611a14565b611754565b90926117bd84896119f4565b156117db576117ce6117d491611a14565b93610e80565b9080611717565b92508061171c565b905015610cb6576080602083015160f81c1038611693565b61180490611acc565b805160006038821015611875575060206101459161182f6116cf60ff611828611a23565b9316611aab565b60001a61183b82610ff9565b535b604051938161185586935180928680870191016100ec565b8201611869825180938680850191016100ec565b010380845201826104d9565b909260019290915b61188784866119f4565b1561189e576117ce61189891611a14565b9261187d565b9092509290926118b061172a82610eb3565b916118c36116cf61174260ff8516611aab565b60001a6118cf84610ff9565b5360015b828111156118e95750505060206101459161183d565b8061190c6116cf61140961140961190661178f611919978a610e5b565b876119f4565b60001a6117a68287611385565b6118d3565b61014590604051906bffffffffffffffffffffffff199060601b1660208201526014815261194b816104a3565b61167f565b9060405161196a8161170260209586830160209181520190565b60009283905b8082106119ca575b5061198561172a82610e39565b91845b83518110156119bc576119b7906119ab6113c46119a486611a14565b9585611385565b871a6117a68287611385565b611988565b50505061014591925061167f565b906119db6114696113c48386611385565b6119ee576119e890611a14565b90611970565b90611978565b81156119fe570490565b634e487b7160e01b600052601260045260246000fd5b6000198114610e345760010190565b60405190611a30826104a3565b6001825260203681840137565b604051611a49816104be565b60008152906000368137565b90611a5f82610516565b611a6c60405191826104d9565b8281528092611a7d601f1991610516565b0190602036910137565b60ff60379116019060ff8211610e3457565b60ff60809116019060ff8211610e3457565b60ff60c09116019060ff8211610e3457565b601f8111610e34576101000a90565b805115611b655790600091825b8151841015611b0757611afb611b0191611af38685611088565b515190610edd565b93611a14565b92611ad9565b611b1391929350611a55565b906020808301936000945b8351861015611b5d57611b51611b5791611b47611b3b8988611088565b51868151910183611b6e565b611af38887611088565b95611a14565b94611b1e565b509350505090565b50610145611a3d565b92905b602093848410611ba65781518152848101809111610e3457938101809111610e345791601f198101908111610e345791611b71565b9290919350600019906020036101000a0190811990511690825116179052565b3d15611bf1573d90611bd782610516565b91611be560405193846104d9565b82523d6000602084013e565b606090565b90601f8111611c0457505050565b600091825260208220906020601f850160051c83019410611c40575b601f0160051c01915b828110611c3557505050565b818155600101611c29565b9092508290611c20565b91909182516001600160401b03811161048357611c7181611c6b8454610cc7565b84611bf6565b602080601f8311600114611ca857508190611ca49394956000926106425750508160011b916000199060031b1c19161790565b9055565b90601f19831695611cbe85600052602060002090565b926000905b888210611cfb57505083600195969710611ce2575b505050811b019055565b015160001960f88460031b161c19169055388080611cd8565b80600185968294968601518155019501930190611cc3565b15611d1a57565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b15611d6657565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b6002546801000000000000000081101561048357806001611dcf9201600255610c7c565b611e2157815191600383101561029e5781546020820151610100600160a81b0360089190911b1660ff949094166001600160a81b03199091161792909217815560409091015161050791600101611c4a565b634e487b7160e01b600052600060045260246000fd5b90611e46606460025410611d13565b80611efd5750611eb5611e5761208d565b9190935b611e89611e8286611e6b87610de2565b9060018060a01b0316600052602052604060002090565b5415611d5f565b611e91610509565b90611e9c8583610cbb565b6001600160a01b03861660208301526040820152611dab565b611ec283611e6b84610de2565b55611ecc81610aa0565b15611ed45790565b6001600160a01b038116600090815260016020526040902061014590805460ff19166001179055565b611eb5611f29611f23604051611f1e81611702876020830160209181520190565b612171565b50611f2f565b93611e5b565b602181510361202b57602181015190805115610cb6576020015160f81c6000600282141580612020575b61200e57806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c0808301919091528152611fb381610488565b519060055afa91611fc2611bc6565b9215611ffc57611fe7611fe1611fda6101459561203d565b9384610edd565b60011690565b156120605790611ff690610e47565b90612060565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b506003821415611f59565b604051636446a2c560e11b8152600490fd5b602081519101519060208110612051575090565b6000199060200360031b1b1690565b604051916020830191825260408301526040825261207d82610468565b905190206001600160a01b031690565b60008060405161209c816104be565b8181526040516120c281611702602082019460208652604080840152606083019061010f565b51906001600160981b015afa6120d6611bc6565b90156120f4576120f1611f236120eb8361203d565b92612171565b91565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b81601f820112156102a357805161214581610516565b9261215360405194856104d9565b818452602082840101116102a35761014591602080850191016100ec565b9060409081516020906121988161170284820197600489528780840152606083019061010f565b51600094859182916005600160981b015afa906121b3611bc6565b9115612212578151820191848183850194031261220e5781810151906001600160401b039182811161220a5784846121ed9284010161212f565b958101519182116122065761014594959650010161212f565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fdfea2646970667358221220ef58c6e1d612015569769985dcaf27936acd7847e6f132b5f930a0a517bb90be64736f6c63430008150033";

type AccountConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AccountConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class Account__factory extends ContractFactory {
  constructor(...args: AccountConstructorParams) {
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
      Account & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): Account__factory {
    return super.connect(runner) as Account__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AccountInterface {
    return new Interface(_abi) as AccountInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): Account {
    return new Contract(address, _abi, runner) as unknown as Account;
  }
}
