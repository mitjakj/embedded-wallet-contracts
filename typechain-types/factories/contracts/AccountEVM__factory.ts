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
    name: "WalletCreate",
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
  "0x6080806040523461002357600160ff196000541617600055611e7c90816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146101075780631b8b921d146101025780631d647605146100fd578063260558a0146100f85780632cc0b254146100f357806337022e98146100ee5780635ced058e146100e95780637d1f3b6f146100e457806382c947b7146100df57806388196f68146100da578063a9059cbb146100d5578063b429afeb146100d0578063d04731d4146100cb578063e341eaa4146100c65763fc9ffe02146100c157600080fd5b6108a0565b6107a8565b6106fc565b6106bd565b610650565b6105d0565b6105a4565b61051b565b6104f4565b61048b565b6103e9565b6103a0565b610335565b6102c3565b610168565b60005b83811061011f5750506000910152565b818101518382015260200161010f565b906020916101488151809281855285808601910161010c565b601f01601f1916010190565b90602061016592818152019061012f565b90565b346102385760031960403682011261023857600435602435916001600160401b0383116102385760e0908336030112610238573360005260016020526101ba600160ff60406000205416151514610935565b60025481106101c881610974565b156102335761022f91610223916002600052600080516020611e278339815191520154906101f78215156109ca565b816000526003602052610214604060002054913690600401610b34565b916001600160a01b0316610cef565b60405191829182610154565b0390f35b6109b4565b600080fd5b600435906001600160a01b038216820361023857565b35906001600160a01b038216820361023857565b6040600319820112610238576004356001600160a01b038116810361023857916024356001600160401b039283821161023857806023830112156102385781600401359384116102385760248483010111610238576024019190565b34610238576102d136610267565b9160009283809333825260016020526102f5600160ff604085205416151514610935565b826040519384928337810182815203925af161030f610bb9565b901561032d5761022f9060405191829160208352602083019061012f565b602081519101fd5b3461023857602036600319011261023857336000526001602052610365600160ff60406000205416151514610935565b6020610372600435610e2a565b60405190807fbd94be19124c4a2cb3c71e447423efd76f6ffd971a8d56a29de827e82d8b7f9b600080a28152f35b34610238576000806103b136610267565b9033845260016020526103cf600160ff604087205416151514610935565b816040519283928337810184815203915afa61030f610bb9565b346102385760403660031901126102385761040261023d565b60ff600054166104515760018060a01b031660005260016020526104316040600020600160ff19825416179055565b61043c602435610e2a565b5061044f600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b34610238576040366003190112610238576104a461023d565b6024358015158091036102385760009133835260016020526104d1600160ff604086205416151514610935565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b34610238576020366003190112610238576040516004356001600160a01b03168152602090f35b346102385760203660031901126102385760043533600052600160205261054e600160ff60406000205416151514610935565b600254811061055c81610974565b15610233576002600052600080516020611e2783398151915201546105828115156109ca565b600052600360205261022f604060002054604051918291829190602083019252565b346102385760203660031901126102385760206001600160a01b036105c761023d565b16604051908152f35b3461023857602036600319011261023857600435336000526001602052610603600160ff60406000205416151514610935565b600254811061061181610974565b156102335761022f906002600052600080516020611e27833981519152015461063b8115156109ca565b60026000526040519081529081906020820190565b346102385760403660031901126102385761066961023d565b6024359060008080809481943383526001602052610692600160ff604086205416151514610935565b829082156106b3575b6001600160a01b031690f1156106ae5780f35b610be9565b6108fc915061069b565b34610238576020366003190112610238576001600160a01b036106de61023d565b166000526001602052602060ff604060002054166040519015158152f35b34610238576020366003190112610238576004356000903382526001602052610730600160ff604085205416151514610935565b600254811061073e81610974565b15610233576002825280600080516020611e2783398151915201908154906107678215156109ca565b818452600360205283604081205560025411156102335760028352908290556001600160a01b03166000908152600160205260409020805460ff1916905580f35b34610238576040366003190112610238576004356107c4610bf5565b503360005260016020526107e4600160ff60406000205416151514610935565b60025481106107f281610974565b156102335761084061022f916002600052600080516020611e27833981519152015461081f8115156109ca565b600081815260036020526040902054602435916001600160a01b0316610f3e565b60408051825181526020808401519082015291810151908201529081906060820190565b602090602060408183019282815285518094520193019160005b82811061088c575050505090565b83518552938101939281019260010161087e565b346102385760008060031936011261093257338152600160209160016020526108d4600160ff604084205416151514610935565b6040519182602060025491828152019460028452600080516020611e2783398151915293905b82821061091d5761022f86610911818a0382610a8e565b60405191829182610864565b845487529586019593830193908301906108fa565b80fd5b1561093c57565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b1561097b57565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b156109d157565b60405162461bcd60e51b815260206004820152600e60248201526d15d85b1b195d081c995b5bdd995960921b6044820152606490fd5b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b03821117610a3857604052565b610a07565b60e081019081106001600160401b03821117610a3857604052565b604081019081106001600160401b03821117610a3857604052565b602081019081106001600160401b03821117610a3857604052565b90601f801991011681019081106001600160401b03821117610a3857604052565b60405190610abc82610a3d565b565b35906001600160401b038216820361023857565b6001600160401b038111610a3857601f01601f191660200190565b81601f8201121561023857803590610b0482610ad2565b92610b126040519485610a8e565b8284526020838301011161023857816000926020809301838601378301015290565b919060e08382031261023857610b48610aaf565b92610b5281610abe565b845260208101356020850152610b6a60408201610abe565b6040850152610b7b60608201610253565b60608501526080810135608085015260a08101356001600160401b0381116102385760c092610bab918301610aed565b60a0850152013560c0830152565b3d15610be4573d90610bca82610ad2565b91610bd86040519384610a8e565b82523d6000602084013e565b606090565b6040513d6000823e3d90fd5b60405190610c0282610a1d565b60006040838281528260208201520152565b634e487b7160e01b600052601160045260246000fd5b6401000003d01990810391908211610c3e57565b610c14565b600019810191908211610c3e57565b6020039060208211610c3e57565b91908203918211610c3e57565b600381901b91906001600160fd1b03811603610c3e57565b908160081b918083046101001490151715610c3e57565b9060238201809211610c3e57565b6004019081600411610c3e57565b9060018201809211610c3e57565b9060048201809211610c3e57565b9060028201809211610c3e57565b91908201809211610c3e57565b610d5f90929192610cfe610bf5565b5060c0830193610d2c855160405190610d1682610a1d565b6000825260006020830152604082015285611148565b604051610d5660208281610d49818301968781519384920161010c565b8101038084520182610a8e565b51902091610f3e565b9060408201805193601a198501948511610c3e57518060011b9080820460021490151715610c3e57610d97610d9c9161016596610ce2565b610c9c565b9052611148565b15610daa57565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b60025468010000000000000000811015610a38576001810180600255811015610233576002600052600080516020611e278339815191520155565b60646002541015610ef95780610eb75750610eaa610165610e49611506565b92905b6001600160a01b0381166000818152600360205260409020909490610e72905415610da3565b610e7b85610def565b610e8f856000526003602052604060002090565b556001600160a01b0316600090815260016020526040902090565b805460ff19166001179055565b610165610eaa610ef4610eee604051610ee981610edb886020830160209181520190565b03601f198101835282610a8e565b6112f1565b506113d5565b610e4c565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b90929192610f4a610bf5565b5060409060008083610fb7610fe6825160209687820152868152610f6d81610a58565b8351908b88830152878252610f8182610a58565b610fda8551610f8f81610a73565b878152610fca875196879460808d87019a610faa8c60049052565b87015260a086019061012f565b601f19958686830301606087015261012f565b908484830301608085015261012f565b03908101835282610a8e565b51906006600160981b015afa91610ffb610bb9565b921561101857505090611010610abc926115f9565b9384916117ec565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b9061105d6020928281519485920161010c565b0190565b6040519061014082018281106001600160401b03821117610a3857604052600982528160005b6101208110611094575050565b806060602080938501015201611087565b8051156102335760200190565b8051600110156102335760400190565b8051600210156102335760600190565b8051600310156102335760800190565b8051600410156102335760a00190565b8051600510156102335760c00190565b8051600610156102335760e00190565b805160071015610233576101000190565b805160081015610233576101200190565b80518210156102335760209160051b010190565b61129660206101659361123c60a061115e611061565b9561118761118261117683516001600160401b031690565b6001600160401b031690565b6118c7565b611190886110a5565b5261119a876110a5565b506111a7858201516118c7565b6111b0886110b2565b526111ba876110b2565b506111d561118261117660408401516001600160401b031690565b6111de886110c2565b526111e8876110c2565b506060810151611200906001600160a01b031661196e565b611209886110d2565b52611213876110d2565b5061122160808201516118c7565b61122a886110e2565b52611234876110e2565b50015161199b565b611245856110f2565b5261124f846110f2565b5061125d60408201516118c7565b61126685611102565b5261127084611102565b5061127b81516118c7565b61128485611112565b5261128e84611112565b5001516118c7565b61129f82611123565b526112a981611123565b50611b08565b81601f820112156102385780516112c581610ad2565b926112d36040519485610a8e565b8184526020828401011161023857610165916020808501910161010c565b90604090815160209061131881610edb84820197600489528780840152606083019061012f565b51600094859182916005600160981b015afa90611333610bb9565b9115611392578151820191848183850194031261138e5781810151906001600160401b039182811161138a57848461136d928401016112af565b95810151918211611386576101659495965001016112af565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fd5b60218151036114d157602181015190805115610233576020015160f81c60006002821415806114c6575b6114b457806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c080830191909152815261145981610a3d565b519060055afa91611468610bb9565b92156114a25761148d611487611480610165956114e3565b9384610ce2565b60011690565b15611c31579061149c90610c2a565b90611c31565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b5060038214156113ff565b604051636446a2c560e11b8152600490fd5b6020815191015190602081106114f7575090565b6000199060200360031b1b1690565b60008060405161151581610a73565b81815260405161153b81610edb602082019460208652604080840152606083019061012f565b51906001600160981b015afa61154f610bb9565b901561156d5761156a610eee611564836114e3565b926112f1565b91565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b8051600210156102335760220190565b8051600110156102335760210190565b8051600310156102335760230190565b8051600410156102335760240190565b908151811015610233570160200190565b90611602610bf5565b9160088151106117b4576001600160f81b0319600360fc1b81611635611627856110a5565b516001600160f81b03191690565b16036117b457600160f91b808261164e611627866115a8565b16036117b45761167261166c611666611627866115b8565b60f81c90565b60ff1690565b9161168561166c611666611627876115c8565b92602184116117b45761169784610caa565b906116b361166c6116666116276116ad86610cb8565b8a6115e8565b93602185116117b4576116d96116cc611627858a6115e8565b6001600160f81b03191690565b036117b457806116f16116ec8688610ce2565b610cc6565b036117b457611701865191610cd4565b036117b45761170f90610cd4565b90600490602185146117c6575b60218414611781575b5090602080928601015194010151916020811061176a575b5060208110611752575b509083526020830152565b61175e61176391610c52565b610c6d565b1c38611747565b61175e61177991949294610c52565b1c913861173d565b61179161162784889694966115e8565b166117b45760206117ab6117a58294610cb8565b92610c43565b93919250611725565b6040516386cd05c560e01b8152600490fd5b809491506117d6611627876115d8565b166117b4576117e6600591610c43565b9361171c565b916040810190601b825280519260208201906020611828835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa156106ae5784516001600160a01b03968716961686900361185b575b505050505050565b61188d8593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa156106ae57516001600160a01b0316036118b557388080808080611853565b604051634532600d60e01b8152600490fd5b906040516118e281610edb6020956020830160209181520190565b6000926000905b80821061194a575b506119036118fe82610c52565b611c90565b9160005b835181101561193c5760019061192961162761192286611cc2565b95856115e8565b871a61193582876115e8565b5301611907565b50505061016591925061199b565b9061195b6116cc61162783866115e8565b61196857600101906118e9565b906118f1565b61016590604051906bffffffffffffffffffffffff199060601b1660208201526014815261199b81610a58565b90600091805192600193600181149081611af0575b50156119bb57509150565b8151936038851015611a1f575092610edb61016592611a1994956119fc6119ec60ff6119e5611c5e565b9616611d03565b60f81b6001600160f81b03191690565b901a611a07846110a5565b535b604051948593602085019061104a565b9061104a565b9091908290600190805b611ac0575b5050611a3c6118fe82610cb8565b92611a546119ec611a4f60ff8516611d03565b611cf1565b811a611a5f856110a5565b5360015b82811115611a8157505050611a1992935090610edb61016592611a09565b80611aa96119ec61166c61166c611aa3611a9e611abb978a610c60565b611d27565b8c611cd1565b831a611ab582886115e8565b53611cc2565b611a63565b9091611acc8388611cd1565b15611aea57611add611ae391611cc2565b92610c85565b9080611a29565b91611a2e565b905015610233576080602083015160f81c10386119b0565b611b1190611d36565b805160006038821015611b825750602061016591611b3c6119ec60ff611b35611c5e565b9316611d15565b60001a611b48826110a5565b535b6040519381611b62869351809286808701910161010c565b8201611b768251809386808501910161010c565b01038084520182610a8e565b909260019290915b611b948486611cd1565b15611bb157611ba5611bab91611cc2565b93610c85565b92611b8a565b909250929092611bc36118fe82610cb8565b91611bd66119ec611a4f60ff8516611d15565b60001a611be2846110a5565b5360015b82811115611bfc57505050602061016591611b4a565b80611c1f6119ec61166c61166c611c19611a9e611c2c978a610c60565b87611cd1565b60001a611ab582876115e8565b611be6565b6040519160208301918252604083015260408252611c4e82610a1d565b905190206001600160a01b031690565b60405190611c6b82610a58565b6001825260203681840137565b604051611c8481610a73565b60008152906000368137565b90611c9a82610ad2565b611ca76040519182610a8e565b8281528092611cb8601f1991610ad2565b0190602036910137565b6000198114610c3e5760010190565b8115611cdb570490565b634e487b7160e01b600052601260045260246000fd5b60ff60379116019060ff8211610c3e57565b60ff60809116019060ff8211610c3e57565b60ff60c09116019060ff8211610c3e57565b601f8111610c3e576101000a90565b805115611dc55790600091825b8151841015611d6c57611d64600191611d5c8685611134565b515190610ce2565b930192611d43565b611d7891929350611c90565b906020808301936000945b8351861015611dbd57611db5600191611dab611d9f8988611134565b51868151910183611dce565b611d5c8887611134565b950194611d83565b509350505090565b50610165611c78565b92905b602093848410611e065781518152848101809111610c3e57938101809111610c3e5791601f198101908111610c3e5791611dd1565b9290919350600019906020036101000a019081199051169082511617905256fe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acea26469706673582212203789f203df13993eae65e734dde77c705383604572ab87305111fd8698397ae364736f6c63430008160033";

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
