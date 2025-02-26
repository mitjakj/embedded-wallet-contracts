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
import type { NonPayableOverrides } from "../../common";
import type {
  AccountEVM,
  AccountEVMInterface,
} from "../../contracts/AccountEVM";

const _abi = [
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
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "publicAddress",
        type: "bytes32",
      },
    ],
    name: "WalletCreated",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "_addr",
        type: "address",
      },
    ],
    name: "addressToBytes32",
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
        internalType: "bytes32",
        name: "_b",
        type: "bytes32",
      },
    ],
    name: "bytes32ToAddress",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "pure",
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
    ],
    name: "createWallet",
    outputs: [
      {
        internalType: "bytes32",
        name: "publicAddress",
        type: "bytes32",
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
        internalType: "bytes32[]",
        name: "",
        type: "bytes32[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "initialController",
        type: "address",
      },
      {
        internalType: "bytes32",
        name: "keypairSecret",
        type: "bytes32",
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
    ],
    name: "removeWallet",
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
    ],
    name: "walletAddress",
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
] as const;

const _bytecode =
  "0x6080806040523461002357600160ff196000541617600055611e9e90816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146101075780631b8b921d146101025780631d647605146100fd578063260558a0146100f85780632cc0b254146100f357806337022e98146100ee5780635ced058e146100e95780637d1f3b6f146100e457806382c947b7146100df57806388196f68146100da578063a9059cbb146100d5578063b429afeb146100d0578063d04731d4146100cb578063e341eaa4146100c65763fc9ffe02146100c157600080fd5b6108c2565b6107ca565b61071e565b6106df565b610672565b6105f2565b6105c6565b61053d565b610516565b6104ad565b6103e9565b6103a0565b610335565b6102c3565b610168565b60005b83811061011f5750506000910152565b818101518382015260200161010f565b906020916101488151809281855285808601910161010c565b601f01601f1916010190565b90602061016592818152019061012f565b90565b346102385760031960403682011261023857600435602435916001600160401b0383116102385760e0908336030112610238573360005260016020526101ba600160ff60406000205416151514610957565b60025481106101c881610996565b156102335761022f91610223916002600052600080516020611e498339815191520154906101f78215156109ec565b816000526003602052610214604060002054913690600401610b56565b916001600160a01b0316610d11565b60405191829182610154565b0390f35b6109d6565b600080fd5b600435906001600160a01b038216820361023857565b35906001600160a01b038216820361023857565b6040600319820112610238576004356001600160a01b038116810361023857916024356001600160401b039283821161023857806023830112156102385781600401359384116102385760248483010111610238576024019190565b34610238576102d136610267565b9160009283809333825260016020526102f5600160ff604085205416151514610957565b826040519384928337810182815203925af161030f610bdb565b901561032d5761022f9060405191829160208352602083019061012f565b602081519101fd5b3461023857602036600319011261023857336000526001602052610365600160ff60406000205416151514610957565b6020610372600435610e4c565b60405190807ff881aa008a081a5e5774e6162db04235bef4d185781a42ed861bb0a74969b9b7600080a28152f35b34610238576000806103b136610267565b9033845260016020526103cf600160ff604087205416151514610957565b816040519283928337810184815203915afa61030f610bdb565b346102385760403660031901126102385761040261023d565b60009060ff825416610473576001600160a01b031681526001602081905260408220805460ff1916909117905561043a602435610e4c565b7ff881aa008a081a5e5774e6162db04235bef4d185781a42ed861bb0a74969b9b78280a2610470600160ff196000541617600055565b80f35b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b34610238576040366003190112610238576104c661023d565b6024358015158091036102385760009133835260016020526104f3600160ff604086205416151514610957565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b34610238576020366003190112610238576040516004356001600160a01b03168152602090f35b3461023857602036600319011261023857600435336000526001602052610570600160ff60406000205416151514610957565b600254811061057e81610996565b15610233576002600052600080516020611e4983398151915201546105a48115156109ec565b600052600360205261022f604060002054604051918291829190602083019252565b346102385760203660031901126102385760206001600160a01b036105e961023d565b16604051908152f35b3461023857602036600319011261023857600435336000526001602052610625600160ff60406000205416151514610957565b600254811061063381610996565b156102335761022f906002600052600080516020611e49833981519152015461065d8115156109ec565b60026000526040519081529081906020820190565b346102385760403660031901126102385761068b61023d565b60243590600080808094819433835260016020526106b4600160ff604086205416151514610957565b829082156106d5575b6001600160a01b031690f1156106d05780f35b610c0b565b6108fc91506106bd565b34610238576020366003190112610238576001600160a01b0361070061023d565b166000526001602052602060ff604060002054166040519015158152f35b34610238576020366003190112610238576004356000903382526001602052610752600160ff604085205416151514610957565b600254811061076081610996565b15610233576002825280600080516020611e4983398151915201908154906107898215156109ec565b818452600360205283604081205560025411156102335760028352908290556001600160a01b03166000908152600160205260409020805460ff1916905580f35b34610238576040366003190112610238576004356107e6610c17565b50336000526001602052610806600160ff60406000205416151514610957565b600254811061081481610996565b156102335761086261022f916002600052600080516020611e4983398151915201546108418115156109ec565b600081815260036020526040902054602435916001600160a01b0316610f60565b60408051825181526020808401519082015291810151908201529081906060820190565b602090602060408183019282815285518094520193019160005b8281106108ae575050505090565b8351855293810193928101926001016108a0565b346102385760008060031936011261095457338152600160209160016020526108f6600160ff604084205416151514610957565b6040519182602060025491828152019460028452600080516020611e4983398151915293905b82821061093f5761022f86610933818a0382610ab0565b60405191829182610886565b8454875295860195938301939083019061091c565b80fd5b1561095e57565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b1561099d57565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b156109f357565b60405162461bcd60e51b815260206004820152600e60248201526d15d85b1b195d081c995b5bdd995960921b6044820152606490fd5b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b03821117610a5a57604052565b610a29565b60e081019081106001600160401b03821117610a5a57604052565b604081019081106001600160401b03821117610a5a57604052565b602081019081106001600160401b03821117610a5a57604052565b90601f801991011681019081106001600160401b03821117610a5a57604052565b60405190610ade82610a5f565b565b35906001600160401b038216820361023857565b6001600160401b038111610a5a57601f01601f191660200190565b81601f8201121561023857803590610b2682610af4565b92610b346040519485610ab0565b8284526020838301011161023857816000926020809301838601378301015290565b919060e08382031261023857610b6a610ad1565b92610b7481610ae0565b845260208101356020850152610b8c60408201610ae0565b6040850152610b9d60608201610253565b60608501526080810135608085015260a08101356001600160401b0381116102385760c092610bcd918301610b0f565b60a0850152013560c0830152565b3d15610c06573d90610bec82610af4565b91610bfa6040519384610ab0565b82523d6000602084013e565b606090565b6040513d6000823e3d90fd5b60405190610c2482610a3f565b60006040838281528260208201520152565b634e487b7160e01b600052601160045260246000fd5b6401000003d01990810391908211610c6057565b610c36565b600019810191908211610c6057565b6020039060208211610c6057565b91908203918211610c6057565b600381901b91906001600160fd1b03811603610c6057565b908160081b918083046101001490151715610c6057565b9060238201809211610c6057565b6004019081600411610c6057565b9060018201809211610c6057565b9060048201809211610c6057565b9060028201809211610c6057565b91908201809211610c6057565b610d8190929192610d20610c17565b5060c0830193610d4e855160405190610d3882610a3f565b600082526000602083015260408201528561116a565b604051610d7860208281610d6b818301968781519384920161010c565b8101038084520182610ab0565b51902091610f60565b9060408201805193601a198501948511610c6057518060011b9080820460021490151715610c6057610db9610dbe9161016596610d04565b610cbe565b905261116a565b15610dcc57565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b60025468010000000000000000811015610a5a576001810180600255811015610233576002600052600080516020611e498339815191520155565b60646002541015610f1b5780610ed95750610ecc610165610e6b611528565b92905b6001600160a01b0381166000818152600360205260409020909490610e94905415610dc5565b610e9d85610e11565b610eb1856000526003602052604060002090565b556001600160a01b0316600090815260016020526040902090565b805460ff19166001179055565b610165610ecc610f16610f10604051610f0b81610efd886020830160209181520190565b03601f198101835282610ab0565b611313565b506113f7565b610e6e565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b90929192610f6c610c17565b5060409060008083610fd9611008825160209687820152868152610f8f81610a7a565b8351908b88830152878252610fa382610a7a565b610ffc8551610fb181610a95565b878152610fec875196879460808d87019a610fcc8c60049052565b87015260a086019061012f565b601f19958686830301606087015261012f565b908484830301608085015261012f565b03908101835282610ab0565b51906006600160981b015afa9161101d610bdb565b921561103a57505090611032610ade9261161b565b93849161180e565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b9061107f6020928281519485920161010c565b0190565b6040519061014082018281106001600160401b03821117610a5a57604052600982528160005b61012081106110b6575050565b8060606020809385010152016110a9565b8051156102335760200190565b8051600110156102335760400190565b8051600210156102335760600190565b8051600310156102335760800190565b8051600410156102335760a00190565b8051600510156102335760c00190565b8051600610156102335760e00190565b805160071015610233576101000190565b805160081015610233576101200190565b80518210156102335760209160051b010190565b6112b860206101659361125e60a0611180611083565b956111a96111a461119883516001600160401b031690565b6001600160401b031690565b6118e9565b6111b2886110c7565b526111bc876110c7565b506111c9858201516118e9565b6111d2886110d4565b526111dc876110d4565b506111f76111a461119860408401516001600160401b031690565b611200886110e4565b5261120a876110e4565b506060810151611222906001600160a01b0316611990565b61122b886110f4565b52611235876110f4565b5061124360808201516118e9565b61124c88611104565b5261125687611104565b5001516119bd565b61126785611114565b5261127184611114565b5061127f60408201516118e9565b61128885611124565b5261129284611124565b5061129d81516118e9565b6112a685611134565b526112b084611134565b5001516118e9565b6112c182611145565b526112cb81611145565b50611b2a565b81601f820112156102385780516112e781610af4565b926112f56040519485610ab0565b8184526020828401011161023857610165916020808501910161010c565b90604090815160209061133a81610efd84820197600489528780840152606083019061012f565b51600094859182916005600160981b015afa90611355610bdb565b91156113b457815182019184818385019403126113b05781810151906001600160401b03918281116113ac57848461138f928401016112d1565b958101519182116113a8576101659495965001016112d1565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fd5b60218151036114f357602181015190805115610233576020015160f81c60006002821415806114e8575b6114d657806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c080830191909152815261147b81610a5f565b519060055afa9161148a610bdb565b92156114c4576114af6114a96114a261016595611505565b9384610d04565b60011690565b15611c5357906114be90610c4c565b90611c53565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b506003821415611421565b604051636446a2c560e11b8152600490fd5b602081519101519060208110611519575090565b6000199060200360031b1b1690565b60008060405161153781610a95565b81815260405161155d81610efd602082019460208652604080840152606083019061012f565b51906001600160981b015afa611571610bdb565b901561158f5761158c610f1061158683611505565b92611313565b91565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b8051600210156102335760220190565b8051600110156102335760210190565b8051600310156102335760230190565b8051600410156102335760240190565b908151811015610233570160200190565b90611624610c17565b9160088151106117d6576001600160f81b0319600360fc1b81611657611649856110c7565b516001600160f81b03191690565b16036117d657600160f91b8082611670611649866115ca565b16036117d65761169461168e611688611649866115da565b60f81c90565b60ff1690565b916116a761168e611688611649876115ea565b92602184116117d6576116b984610ccc565b906116d561168e6116886116496116cf86610cda565b8a61160a565b93602185116117d6576116fb6116ee611649858a61160a565b6001600160f81b03191690565b036117d6578061171361170e8688610d04565b610ce8565b036117d657611723865191610cf6565b036117d65761173190610cf6565b90600490602185146117e8575b602184146117a3575b5090602080928601015194010151916020811061178c575b5060208110611774575b509083526020830152565b61178061178591610c74565b610c8f565b1c38611769565b61178061179b91949294610c74565b1c913861175f565b6117b3611649848896949661160a565b166117d65760206117cd6117c78294610cda565b92610c65565b93919250611747565b6040516386cd05c560e01b8152600490fd5b809491506117f8611649876115fa565b166117d657611808600591610c65565b9361173e565b916040810190601b82528051926020820190602061184a835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa156106d05784516001600160a01b03968716961686900361187d575b505050505050565b6118af8593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa156106d057516001600160a01b0316036118d757388080808080611875565b604051634532600d60e01b8152600490fd5b9060405161190481610efd6020956020830160209181520190565b6000926000905b80821061196c575b5061192561192082610c74565b611cb2565b9160005b835181101561195e5760019061194b61164961194486611ce4565b958561160a565b871a611957828761160a565b5301611929565b5050506101659192506119bd565b9061197d6116ee611649838661160a565b61198a576001019061190b565b90611913565b61016590604051906bffffffffffffffffffffffff199060601b166020820152601481526119bd81610a7a565b90600091805192600193600181149081611b12575b50156119dd57509150565b8151936038851015611a41575092610efd61016592611a3b9495611a1e611a0e60ff611a07611c80565b9616611d25565b60f81b6001600160f81b03191690565b901a611a29846110c7565b535b604051948593602085019061106c565b9061106c565b9091908290600190805b611ae2575b5050611a5e61192082610cda565b92611a76611a0e611a7160ff8516611d25565b611d13565b811a611a81856110c7565b5360015b82811115611aa357505050611a3b92935090610efd61016592611a2b565b80611acb611a0e61168e61168e611ac5611ac0611add978a610c82565b611d49565b8c611cf3565b831a611ad7828861160a565b53611ce4565b611a85565b9091611aee8388611cf3565b15611b0c57611aff611b0591611ce4565b92610ca7565b9080611a4b565b91611a50565b905015610233576080602083015160f81c10386119d2565b611b3390611d58565b805160006038821015611ba45750602061016591611b5e611a0e60ff611b57611c80565b9316611d37565b60001a611b6a826110c7565b535b6040519381611b84869351809286808701910161010c565b8201611b988251809386808501910161010c565b01038084520182610ab0565b909260019290915b611bb68486611cf3565b15611bd357611bc7611bcd91611ce4565b93610ca7565b92611bac565b909250929092611be561192082610cda565b91611bf8611a0e611a7160ff8516611d37565b60001a611c04846110c7565b5360015b82811115611c1e57505050602061016591611b6c565b80611c41611a0e61168e61168e611c3b611ac0611c4e978a610c82565b87611cf3565b60001a611ad7828761160a565b611c08565b6040519160208301918252604083015260408252611c7082610a3f565b905190206001600160a01b031690565b60405190611c8d82610a7a565b6001825260203681840137565b604051611ca681610a95565b60008152906000368137565b90611cbc82610af4565b611cc96040519182610ab0565b8281528092611cda601f1991610af4565b0190602036910137565b6000198114610c605760010190565b8115611cfd570490565b634e487b7160e01b600052601260045260246000fd5b60ff60379116019060ff8211610c6057565b60ff60809116019060ff8211610c6057565b60ff60c09116019060ff8211610c6057565b601f8111610c60576101000a90565b805115611de75790600091825b8151841015611d8e57611d86600191611d7e8685611156565b515190610d04565b930192611d65565b611d9a91929350611cb2565b906020808301936000945b8351861015611ddf57611dd7600191611dcd611dc18988611156565b51868151910183611df0565b611d7e8887611156565b950194611da5565b509350505090565b50610165611c9a565b92905b602093848410611e285781518152848101809111610c6057938101809111610c605791601f198101908111610c605791611df3565b9290919350600019906020036101000a019081199051169082511617905256fe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acea26469706673582212200d68338de82b2cab952315c1b702cbed51deec5159ec8668e87e43f1d0b51ac264736f6c63430008160033";

type AccountEVMConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AccountEVMConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class AccountEVM__factory extends ContractFactory {
  constructor(...args: AccountEVMConstructorParams) {
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
      AccountEVM & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): AccountEVM__factory {
    return super.connect(runner) as AccountEVM__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AccountEVMInterface {
    return new Interface(_abi) as AccountEVMInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): AccountEVM {
    return new Contract(address, _abi, runner) as unknown as AccountEVM;
  }
}
