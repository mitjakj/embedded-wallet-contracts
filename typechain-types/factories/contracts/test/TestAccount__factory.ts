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
  TestAccount,
  TestAccountInterface,
} from "../../../contracts/test/TestAccount";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "addr",
        type: "address",
      },
    ],
    name: "CloneCreated",
    type: "event",
  },
  {
    inputs: [],
    name: "testClone",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x6080806040523461008557613c678181016001600160401b0381118382101761006f578291610203833903906000f0801561006357600080546001600160a01b0319166001600160a01b0392909216919091179055604051610178908161008b8239f35b6040513d6000823e3d90fd5b634e487b7160e01b600052604160045260246000fd5b600080fdfe608080604052600436101561001357600080fd5b600090813560e01c63b8b1d0cb1461002a57600080fd5b3461013e578160031936011261013e5760018060a01b03906020816064818686815416631cc42c0760e31b83523360048401528160248401528160448401525af19081156101335783916100aa575b506020907fbe2f3d28fdeb5839123d65fd47ec2f5915c715d2b527b9e229123706fdecfc859260405191168152a180f35b905060203d60201161012c575b601f8101601f1916820167ffffffffffffffff8111838210176101185760209183916040528101031261011457518181168103610114577fbe2f3d28fdeb5839123d65fd47ec2f5915c715d2b527b9e229123706fdecfc85610079565b8280fd5b634e487b7160e01b85526041600452602485fd5b503d6100b7565b6040513d85823e3d90fd5b5080fdfea2646970667358221220e7a9d273b64e8a3a9831a86b71ee2ffa8b3a758fdaeb3c214f3185786282ac5f64736f6c6343000816003360a080604052346100cc57306080527ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a009081549060ff8260401c166100bd57506001600160401b036002600160401b031982821601610078575b604051613b9590816100d2823960805181818161033001526104680152f35b6001600160401b031990911681179091556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1388080610059565b63f92ee8a960e01b8152600490fd5b600080fdfe6080604052600436101561001257600080fd5b60003560e01c806301ffc9a7146100d7578063248a9ca3146100d25780632f2ff15d146100cd57806336568abe146100c85780634f1ef286146100c357806352d1902d146100be5780638129fc1c146100b957806391d14854146100b4578063a217fddf146100af578063ad3cb1cc146100aa578063d547741f146100a55763e6216038146100a057600080fd5b610728565b6106dc565b61065f565b610643565b6105e4565b6104c0565b610455565b6102b8565b6101e8565b61019a565b610132565b3461012d57602036600319011261012d5760043563ffffffff60e01b811680910361012d57602090637965db0b60e01b811490811561011c575b506040519015158152f35b6301ffc9a760e01b14905038610111565b600080fd5b3461012d57602036600319011261012d57600435600052600080516020613b208339815191526020526020600160406000200154604051908152f35b602435906001600160a01b038216820361012d57565b600435906001600160a01b038216820361012d57565b3461012d57604036600319011261012d576101e66004356101b961016e565b9080600052600080516020613b208339815191526020526101e16001604060002001546109a8565b6109fa565b005b3461012d57604036600319011261012d5761020161016e565b336001600160a01b0382160361021d576101e690600435610a9b565b60405163334bd91960e11b8152600490fd5b634e487b7160e01b600052604160045260246000fd5b67ffffffffffffffff811161025957604052565b61022f565b6040810190811067ffffffffffffffff82111761025957604052565b90601f8019910116810190811067ffffffffffffffff82111761025957604052565b67ffffffffffffffff811161025957601f01601f191660200190565b60408060031936011261012d576102cd610184565b60243567ffffffffffffffff811161012d573660238201121561012d5780600401356102f88161029c565b916103058551938461027a565b818352366024838301011161012d578160009260246020930183860137830101526001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000811630811490811561042e575b5061041d57602060049161036e610950565b85516352d1902d60e01b8152928391829087165afa600091816103ec575b506103b1578351634c9c8ce360e01b81526001600160a01b0384166004820152602490fd5b600080516020613b0083398151915281939293036103d3576101e68383610b9a565b8351632a87526960e21b81526004810191909152602490fd5b61040f91925060203d602011610416575b610407818361027a565b810190610b33565b903861038c565b503d6103fd565b835163703e46dd60e11b8152600490fd5b905081600080516020613b00833981519152541614153861035c565b600091031261012d57565b3461012d57600036600319011261012d577f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031630036104ae576020604051600080516020613b008339815191528152f35b60405163703e46dd60e11b8152600490fd5b600036600319011261012d57600080516020613b408339815191525467ffffffffffffffff60ff8260401c16159116801590816105dc575b60011490816105d2575b1590816105c9575b506105b757600080516020613b40833981519152805467ffffffffffffffff191660011790558061058d575b61053e61077b565b61054457005b600080516020613b40833981519152805460ff60401b19169055604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1005b600080516020613b40833981519152805460ff60401b191668010000000000000000179055610536565b60405163f92ee8a960e01b8152600490fd5b9050153861050a565b303b159150610502565b8291506104f8565b3461012d57604036600319011261012d57602060ff61063761060461016e565b600435600052600080516020613b20833981519152845260406000209060018060a01b0316600052602052604060002090565b54166040519015158152f35b3461012d57600036600319011261012d57602060405160008152f35b3461012d57600036600319011261012d57604080519061067e8261025e565b60058252602090640352e302e360dc1b6020840152604051916020835283519182602085015260005b8381106106c95784604081866000838284010152601f80199101168101030190f35b85810183015185820183015282016106a7565b3461012d57604036600319011261012d576101e66004356106fb61016e565b9080600052600080516020613b208339815191526020526107236001604060002001546109a8565b610a9b565b3461012d57606036600319011261012d57610741610184565b602435600381101561012d5760209161075d916044359161084a565b6040516001600160a01b039091168152f35b6040513d6000823e3d90fd5b610783610c41565b61078b610c41565b60405167ffffffffffffffff90611ea580820183811183821017610259578291610d16833903906000f080156108255760018060a01b03166bffffffffffffffffffffffff60a01b600054161760005560405190610f45908183019083821090821117610259578291612bbb833903906000f0801561082557600180546001600160a01b0319166001600160a01b03909216919091179055565b61076f565b6003111561083457565b634e487b7160e01b600052602160045260246000fd5b91906108558161082a565b806108e5575060005461088990610878908190610884906001600160a01b031682565b6001600160a01b031690565b610b42565b91823b1561012d57604051630b302c9560e21b81526001600160a01b03919091166004820152602481019190915260008160448183865af18015610825576108cf575090565b806108dc6108e292610245565b8061044a565b90565b806108f160019261082a565b036109135760015461088990610878908190610884906001600160a01b031682565b60405162461bcd60e51b8152602060048201526015602482015274416374696f6e206e6f7420737570706f727465642160581b6044820152606490fd5b3360009081527fb7db2dd08fcb62d0c9e08c51941cae53c267786a0b75803fb7960902fc8ef97d602052604090205460ff161561098957565b60405163e2517d3f60e01b815233600482015260006024820152604490fd5b6000818152600080516020613b208339815191526020908152604080832033845290915290205460ff16156109da5750565b60405163e2517d3f60e01b81523360048201526024810191909152604490fd5b6000818152600080516020613b20833981519152602081815260408084206001600160a01b038716855290915282205491929160ff16610a9457818352602090815260408084206001600160a01b038616600090815292529020805460ff1916600117905533926001600160a01b0316917f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d9080a4600190565b5050905090565b6000818152600080516020613b20833981519152602081815260408084206001600160a01b038716855290915282205491929160ff1615610a9457818352602090815260408084206001600160a01b038616600090815292529020805460ff1916905533926001600160a01b0316917ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b9080a4600190565b9081602091031261012d575190565b604051733d602d80600a3d3981f3363d3d373d3d3d363d7360601b815260609190911b6bffffffffffffffffffffffff191660148201526e5af43d82803e903d91602b57fd5bf360881b60288201526037906000f090565b90813b15610c2057600080516020613b0083398151915280546001600160a01b0319166001600160a01b0384169081179091557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a2805115610c0557610c0291610c70565b50565b505034610c0e57565b60405163b398979f60e01b8152600490fd5b604051634c9c8ce360e01b81526001600160a01b0383166004820152602490fd5b60ff600080516020613b408339815191525460401c1615610c5e57565b604051631afcd79f60e31b8152600490fd5b6000806108e293602081519101845af43d15610cae573d91610c918361029c565b92610c9f604051948561027a565b83523d6000602085013e610cb2565b6060915b90610cd95750805115610cc757805190602001fd5b60405163d6bda27560e01b8152600490fd5b81511580610d0c575b610cea575090565b604051639996b31560e01b81526001600160a01b039091166004820152602490fd5b50803b15610ce256fe6080806040523461002357600160ff196000541617600055611e7c90816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146101075780631b8b921d146101025780631d647605146100fd578063260558a0146100f85780632cc0b254146100f357806337022e98146100ee5780635ced058e146100e95780637d1f3b6f146100e457806382c947b7146100df57806388196f68146100da578063a9059cbb146100d5578063b429afeb146100d0578063d04731d4146100cb578063e341eaa4146100c65763fc9ffe02146100c157600080fd5b6108a0565b6107a8565b6106fc565b6106bd565b610650565b6105d0565b6105a4565b61051b565b6104f4565b61048b565b6103e9565b6103a0565b610335565b6102c3565b610168565b60005b83811061011f5750506000910152565b818101518382015260200161010f565b906020916101488151809281855285808601910161010c565b601f01601f1916010190565b90602061016592818152019061012f565b90565b346102385760031960403682011261023857600435602435916001600160401b0383116102385760e0908336030112610238573360005260016020526101ba600160ff60406000205416151514610935565b60025481106101c881610974565b156102335761022f91610223916002600052600080516020611e278339815191520154906101f78215156109ca565b816000526003602052610214604060002054913690600401610b34565b916001600160a01b0316610cef565b60405191829182610154565b0390f35b6109b4565b600080fd5b600435906001600160a01b038216820361023857565b35906001600160a01b038216820361023857565b6040600319820112610238576004356001600160a01b038116810361023857916024356001600160401b039283821161023857806023830112156102385781600401359384116102385760248483010111610238576024019190565b34610238576102d136610267565b9160009283809333825260016020526102f5600160ff604085205416151514610935565b826040519384928337810182815203925af161030f610bb9565b901561032d5761022f9060405191829160208352602083019061012f565b602081519101fd5b3461023857602036600319011261023857336000526001602052610365600160ff60406000205416151514610935565b6020610372600435610e2a565b60405190807fbd94be19124c4a2cb3c71e447423efd76f6ffd971a8d56a29de827e82d8b7f9b600080a28152f35b34610238576000806103b136610267565b9033845260016020526103cf600160ff604087205416151514610935565b816040519283928337810184815203915afa61030f610bb9565b346102385760403660031901126102385761040261023d565b60ff600054166104515760018060a01b031660005260016020526104316040600020600160ff19825416179055565b61043c602435610e2a565b5061044f600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b34610238576040366003190112610238576104a461023d565b6024358015158091036102385760009133835260016020526104d1600160ff604086205416151514610935565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b34610238576020366003190112610238576040516004356001600160a01b03168152602090f35b346102385760203660031901126102385760043533600052600160205261054e600160ff60406000205416151514610935565b600254811061055c81610974565b15610233576002600052600080516020611e2783398151915201546105828115156109ca565b600052600360205261022f604060002054604051918291829190602083019252565b346102385760203660031901126102385760206001600160a01b036105c761023d565b16604051908152f35b3461023857602036600319011261023857600435336000526001602052610603600160ff60406000205416151514610935565b600254811061061181610974565b156102335761022f906002600052600080516020611e27833981519152015461063b8115156109ca565b60026000526040519081529081906020820190565b346102385760403660031901126102385761066961023d565b6024359060008080809481943383526001602052610692600160ff604086205416151514610935565b829082156106b3575b6001600160a01b031690f1156106ae5780f35b610be9565b6108fc915061069b565b34610238576020366003190112610238576001600160a01b036106de61023d565b166000526001602052602060ff604060002054166040519015158152f35b34610238576020366003190112610238576004356000903382526001602052610730600160ff604085205416151514610935565b600254811061073e81610974565b15610233576002825280600080516020611e2783398151915201908154906107678215156109ca565b818452600360205283604081205560025411156102335760028352908290556001600160a01b03166000908152600160205260409020805460ff1916905580f35b34610238576040366003190112610238576004356107c4610bf5565b503360005260016020526107e4600160ff60406000205416151514610935565b60025481106107f281610974565b156102335761084061022f916002600052600080516020611e27833981519152015461081f8115156109ca565b600081815260036020526040902054602435916001600160a01b0316610f3e565b60408051825181526020808401519082015291810151908201529081906060820190565b602090602060408183019282815285518094520193019160005b82811061088c575050505090565b83518552938101939281019260010161087e565b346102385760008060031936011261093257338152600160209160016020526108d4600160ff604084205416151514610935565b6040519182602060025491828152019460028452600080516020611e2783398151915293905b82821061091d5761022f86610911818a0382610a8e565b60405191829182610864565b845487529586019593830193908301906108fa565b80fd5b1561093c57565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b1561097b57565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b156109d157565b60405162461bcd60e51b815260206004820152600e60248201526d15d85b1b195d081c995b5bdd995960921b6044820152606490fd5b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b03821117610a3857604052565b610a07565b60e081019081106001600160401b03821117610a3857604052565b604081019081106001600160401b03821117610a3857604052565b602081019081106001600160401b03821117610a3857604052565b90601f801991011681019081106001600160401b03821117610a3857604052565b60405190610abc82610a3d565b565b35906001600160401b038216820361023857565b6001600160401b038111610a3857601f01601f191660200190565b81601f8201121561023857803590610b0482610ad2565b92610b126040519485610a8e565b8284526020838301011161023857816000926020809301838601378301015290565b919060e08382031261023857610b48610aaf565b92610b5281610abe565b845260208101356020850152610b6a60408201610abe565b6040850152610b7b60608201610253565b60608501526080810135608085015260a08101356001600160401b0381116102385760c092610bab918301610aed565b60a0850152013560c0830152565b3d15610be4573d90610bca82610ad2565b91610bd86040519384610a8e565b82523d6000602084013e565b606090565b6040513d6000823e3d90fd5b60405190610c0282610a1d565b60006040838281528260208201520152565b634e487b7160e01b600052601160045260246000fd5b6401000003d01990810391908211610c3e57565b610c14565b600019810191908211610c3e57565b6020039060208211610c3e57565b91908203918211610c3e57565b600381901b91906001600160fd1b03811603610c3e57565b908160081b918083046101001490151715610c3e57565b9060238201809211610c3e57565b6004019081600411610c3e57565b9060018201809211610c3e57565b9060048201809211610c3e57565b9060028201809211610c3e57565b91908201809211610c3e57565b610d5f90929192610cfe610bf5565b5060c0830193610d2c855160405190610d1682610a1d565b6000825260006020830152604082015285611148565b604051610d5660208281610d49818301968781519384920161010c565b8101038084520182610a8e565b51902091610f3e565b9060408201805193601a198501948511610c3e57518060011b9080820460021490151715610c3e57610d97610d9c9161016596610ce2565b610c9c565b9052611148565b15610daa57565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b60025468010000000000000000811015610a38576001810180600255811015610233576002600052600080516020611e278339815191520155565b60646002541015610ef95780610eb75750610eaa610165610e49611506565b92905b6001600160a01b0381166000818152600360205260409020909490610e72905415610da3565b610e7b85610def565b610e8f856000526003602052604060002090565b556001600160a01b0316600090815260016020526040902090565b805460ff19166001179055565b610165610eaa610ef4610eee604051610ee981610edb886020830160209181520190565b03601f198101835282610a8e565b6112f1565b506113d5565b610e4c565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b90929192610f4a610bf5565b5060409060008083610fb7610fe6825160209687820152868152610f6d81610a58565b8351908b88830152878252610f8182610a58565b610fda8551610f8f81610a73565b878152610fca875196879460808d87019a610faa8c60049052565b87015260a086019061012f565b601f19958686830301606087015261012f565b908484830301608085015261012f565b03908101835282610a8e565b51906006600160981b015afa91610ffb610bb9565b921561101857505090611010610abc926115f9565b9384916117ec565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b9061105d6020928281519485920161010c565b0190565b6040519061014082018281106001600160401b03821117610a3857604052600982528160005b6101208110611094575050565b806060602080938501015201611087565b8051156102335760200190565b8051600110156102335760400190565b8051600210156102335760600190565b8051600310156102335760800190565b8051600410156102335760a00190565b8051600510156102335760c00190565b8051600610156102335760e00190565b805160071015610233576101000190565b805160081015610233576101200190565b80518210156102335760209160051b010190565b61129660206101659361123c60a061115e611061565b9561118761118261117683516001600160401b031690565b6001600160401b031690565b6118c7565b611190886110a5565b5261119a876110a5565b506111a7858201516118c7565b6111b0886110b2565b526111ba876110b2565b506111d561118261117660408401516001600160401b031690565b6111de886110c2565b526111e8876110c2565b506060810151611200906001600160a01b031661196e565b611209886110d2565b52611213876110d2565b5061122160808201516118c7565b61122a886110e2565b52611234876110e2565b50015161199b565b611245856110f2565b5261124f846110f2565b5061125d60408201516118c7565b61126685611102565b5261127084611102565b5061127b81516118c7565b61128485611112565b5261128e84611112565b5001516118c7565b61129f82611123565b526112a981611123565b50611b08565b81601f820112156102385780516112c581610ad2565b926112d36040519485610a8e565b8184526020828401011161023857610165916020808501910161010c565b90604090815160209061131881610edb84820197600489528780840152606083019061012f565b51600094859182916005600160981b015afa90611333610bb9565b9115611392578151820191848183850194031261138e5781810151906001600160401b039182811161138a57848461136d928401016112af565b95810151918211611386576101659495965001016112af565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fd5b60218151036114d157602181015190805115610233576020015160f81c60006002821415806114c6575b6114b457806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c080830191909152815261145981610a3d565b519060055afa91611468610bb9565b92156114a25761148d611487611480610165956114e3565b9384610ce2565b60011690565b15611c31579061149c90610c2a565b90611c31565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b5060038214156113ff565b604051636446a2c560e11b8152600490fd5b6020815191015190602081106114f7575090565b6000199060200360031b1b1690565b60008060405161151581610a73565b81815260405161153b81610edb602082019460208652604080840152606083019061012f565b51906001600160981b015afa61154f610bb9565b901561156d5761156a610eee611564836114e3565b926112f1565b91565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b8051600210156102335760220190565b8051600110156102335760210190565b8051600310156102335760230190565b8051600410156102335760240190565b908151811015610233570160200190565b90611602610bf5565b9160088151106117b4576001600160f81b0319600360fc1b81611635611627856110a5565b516001600160f81b03191690565b16036117b457600160f91b808261164e611627866115a8565b16036117b45761167261166c611666611627866115b8565b60f81c90565b60ff1690565b9161168561166c611666611627876115c8565b92602184116117b45761169784610caa565b906116b361166c6116666116276116ad86610cb8565b8a6115e8565b93602185116117b4576116d96116cc611627858a6115e8565b6001600160f81b03191690565b036117b457806116f16116ec8688610ce2565b610cc6565b036117b457611701865191610cd4565b036117b45761170f90610cd4565b90600490602185146117c6575b60218414611781575b5090602080928601015194010151916020811061176a575b5060208110611752575b509083526020830152565b61175e61176391610c52565b610c6d565b1c38611747565b61175e61177991949294610c52565b1c913861173d565b61179161162784889694966115e8565b166117b45760206117ab6117a58294610cb8565b92610c43565b93919250611725565b6040516386cd05c560e01b8152600490fd5b809491506117d6611627876115d8565b166117b4576117e6600591610c43565b9361171c565b916040810190601b825280519260208201906020611828835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa156106ae5784516001600160a01b03968716961686900361185b575b505050505050565b61188d8593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa156106ae57516001600160a01b0316036118b557388080808080611853565b604051634532600d60e01b8152600490fd5b906040516118e281610edb6020956020830160209181520190565b6000926000905b80821061194a575b506119036118fe82610c52565b611c90565b9160005b835181101561193c5760019061192961162761192286611cc2565b95856115e8565b871a61193582876115e8565b5301611907565b50505061016591925061199b565b9061195b6116cc61162783866115e8565b61196857600101906118e9565b906118f1565b61016590604051906bffffffffffffffffffffffff199060601b1660208201526014815261199b81610a58565b90600091805192600193600181149081611af0575b50156119bb57509150565b8151936038851015611a1f575092610edb61016592611a1994956119fc6119ec60ff6119e5611c5e565b9616611d03565b60f81b6001600160f81b03191690565b901a611a07846110a5565b535b604051948593602085019061104a565b9061104a565b9091908290600190805b611ac0575b5050611a3c6118fe82610cb8565b92611a546119ec611a4f60ff8516611d03565b611cf1565b811a611a5f856110a5565b5360015b82811115611a8157505050611a1992935090610edb61016592611a09565b80611aa96119ec61166c61166c611aa3611a9e611abb978a610c60565b611d27565b8c611cd1565b831a611ab582886115e8565b53611cc2565b611a63565b9091611acc8388611cd1565b15611aea57611add611ae391611cc2565b92610c85565b9080611a29565b91611a2e565b905015610233576080602083015160f81c10386119b0565b611b1190611d36565b805160006038821015611b825750602061016591611b3c6119ec60ff611b35611c5e565b9316611d15565b60001a611b48826110a5565b535b6040519381611b62869351809286808701910161010c565b8201611b768251809386808501910161010c565b01038084520182610a8e565b909260019290915b611b948486611cd1565b15611bb157611ba5611bab91611cc2565b93610c85565b92611b8a565b909250929092611bc36118fe82610cb8565b91611bd66119ec611a4f60ff8516611d15565b60001a611be2846110a5565b5360015b82811115611bfc57505050602061016591611b4a565b80611c1f6119ec61166c61166c611c19611a9e611c2c978a610c60565b87611cd1565b60001a611ab582876115e8565b611be6565b6040519160208301918252604083015260408252611c4e82610a1d565b905190206001600160a01b031690565b60405190611c6b82610a58565b6001825260203681840137565b604051611c8481610a73565b60008152906000368137565b90611c9a82610ad2565b611ca76040519182610a8e565b8281528092611cb8601f1991610ad2565b0190602036910137565b6000198114610c3e5760010190565b8115611cdb570490565b634e487b7160e01b600052601260045260246000fd5b60ff60379116019060ff8211610c3e57565b60ff60809116019060ff8211610c3e57565b60ff60c09116019060ff8211610c3e57565b601f8111610c3e576101000a90565b805115611dc55790600091825b8151841015611d6c57611d64600191611d5c8685611134565b515190610ce2565b930192611d43565b611d7891929350611c90565b906020808301936000945b8351861015611dbd57611db5600191611dab611d9f8988611134565b51868151910183611dce565b611d5c8887611134565b950194611d83565b509350505090565b50610165611c78565b92905b602093848410611e065781518152848101809111610c3e57938101809111610c3e5791601f198101908111610c3e5791611dd1565b9290919350600019906020036101000a019081199051169082511617905256fe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acea264697066735822122057b6d6a2b26d535512abb7f9c95c43eea07893c19ce11770b2e48455e9cb53bf64736f6c634300081600336080806040523461002357600160ff196000541617600055610f1c90816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c80631b8b921d146100d75780631d647605146100d2578063260558a0146100cd5780632cc0b254146100c857806337022e98146100c35780637d1f3b6f146100be57806388196f68146100b95780639b3d270a146100b4578063a9059cbb146100af578063b429afeb146100aa578063d04731d4146100a55763fc9ffe02146100a057600080fd5b61076d565b6106ab565b61066c565b6105f8565b610573565b61047e565b6103f0565b610386565b6102da565b610291565b610226565b6101b0565b600435906001600160a01b03821682036100f257565b600080fd5b60406003198201126100f2576004356001600160a01b03811681036100f2579160243567ffffffffffffffff928382116100f257806023830112156100f25781600401359384116100f257602484830101116100f2576024019190565b60005b8381106101675750506000910152565b8181015183820152602001610157565b9060209161019081518092818552858086019101610154565b601f01601f1916010190565b9060206101ad928181520190610177565b90565b346100f2576101be366100f7565b9160009283809333825260016020526101e2600160ff604085205416151514610802565b826040519384928337810182815203925af16101fc610865565b901561021e5761021a90604051918291602083526020830190610177565b0390f35b602081519101fd5b346100f25760203660031901126100f257336000526001602052610256600160ff60406000205416151514610802565b6020610263600435610b46565b60405190807fbd94be19124c4a2cb3c71e447423efd76f6ffd971a8d56a29de827e82d8b7f9b600080a28152f35b346100f2576000806102a2366100f7565b9033845260016020526102c0600160ff604087205416151514610802565b816040519283928337810184815203915afa6101fc610865565b346100f25760403660031901126100f2576102f36100dc565b60ff600054166103425760018060a01b031660005260016020526103226040600020600160ff19825416179055565b61032d602435610b46565b50610340600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b801515036100f257565b346100f25760403660031901126100f25761039f6100dc565b6024356103ab8161037c565b60009133835260016020526103cb600160ff604086205416151514610802565b60018060a01b031682526001602052604082209060ff80198354169115151617905580f35b346100f25760203660031901126100f257600435336000526001602052610423600160ff60406000205416151514610802565b600254811061043181610895565b15610479576002600052600080516020610ec783398151915201546104578115156108eb565b600052600360205261021a604060002054604051918291829190602083019252565b6108d5565b346100f25760203660031901126100f2576004353360005260016020526104b1600160ff60406000205416151514610802565b60025481106104bf81610895565b156104795761021a906002600052600080516020610ec783398151915201546104e98115156108eb565b60026000526040519081529081906020820190565b634e487b7160e01b600052604160045260246000fd5b6040810190811067ffffffffffffffff82111761053057604052565b6104fe565b90601f8019910116810190811067ffffffffffffffff82111761053057604052565b67ffffffffffffffff811161053057601f01601f191660200190565b346100f25760403660031901126100f25760243567ffffffffffffffff81116100f257366023820112156100f2578060040135906105b082610557565b6105bd6040519182610535565b82815236602484840101116100f257600060208461021a9560246105ec96018386013783010152600435610928565b6040519182918261019c565b346100f25760403660031901126100f2576106116100dc565b602435906000808080948194338352600160205261063a600160ff604086205416151514610802565b82908215610662575b6001600160a01b031690f1156106565780f35b604051903d90823e3d90fd5b6108fc9150610643565b346100f25760203660031901126100f2576001600160a01b0361068d6100dc565b166000526001602052602060ff604060002054166040519015158152f35b346100f25760203660031901126100f25760043560009033825260016020526106df600160ff604085205416151514610802565b60025481106106ed81610895565b15610479576002825280600080516020610ec7833981519152019081546107158115156108eb565b8352600360205282604081205560025411156104795781905580f35b602090602060408183019282815285518094520193019160005b828110610759575050505090565b83518552938101939281019260010161074b565b346100f2576000806003193601126107ff57338152600160209160016020526107a1600160ff604084205416151514610802565b6040519182602060025491828152019460028452600080516020610ec783398151915293905b8282106107ea5761021a866107de818a0382610535565b60405191829182610731565b845487529586019593830193908301906107c7565b80fd5b1561080957565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b604051906020820182811067ffffffffffffffff8211176105305760405260008252565b3d15610890573d9061087682610557565b916108846040519384610535565b82523d6000602084013e565b606090565b1561089c57565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b156108f257565b60405162461bcd60e51b815260206004820152600e60248201526d15d85b1b195d081c995b5bdd995960921b6044820152606490fd5b9060009133835260206001815260409361094c600160ff8784205416151514610802565b600254831061095a81610895565b1561047957610a109260028252600080516020610ec783398151915201546109838115156108eb565b81526003825280856109e16109ad82842054835190878201528681526109a881610514565b610c7a565b6109b8979197610a77565b90610a046109f4865195869360808c8601996109d48b60069052565b86015260a0850190610177565b601f199485858303016060860152610177565b838382030160808401528b610177565b03908101835282610535565b51906006600160981b015afa93610a25610865565b9415610a45575050610a41918391610a3b610a77565b90610d74565b5090565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b60405190610a8482610514565b600982526873756273747261746560b81b6020830152565b602081519101519060208110610ab0575090565b6000199060200360031b1b1690565b15610ac657565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b60025468010000000000000000811015610530576001810180600255811015610479576002600052600080516020610ec78339815191520155565b60646002541015610bf35780610bc15750610b67610b62610841565b610e47565b610b82610b7c610b7683610c7a565b50610a9c565b91610a9c565b610ba0610b99836000526003602052604060002090565b5415610abf565b610ba982610b0b565b610bbd826000526003602052604060002090565b5590565b610bed610b766040516109a881610bdf866020830160209181520190565b03601f198101835282610535565b90610b82565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b81601f820112156100f2578051610c4e81610557565b92610c5c6040519485610535565b818452602082840101116100f2576101ad9160208085019101610154565b906040908151602090610ca181610bdf848201976006895287808401526060830190610177565b51600094859182916005600160981b015afa90610cbc610865565b9115610d1c5781518201918481838501940312610d1857818101519067ffffffffffffffff91828111610d14578484610cf792840101610c38565b95810151918211610d10576101ad949596500101610c38565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fd5b908160209103126100f257516101ad8161037c565b90610de4610dd49160009594610a048796604051958693610dc4610db1602087019a610da08c60069052565b60a0604089015260c0880190610177565b601f199788888303016060890152610177565b9086868303016080870152610177565b90848483030160a0850152610177565b51906007600160981b015afa610df8610865565b9015610e1157806020806101ad93518301019101610d5f565b60405162461bcd60e51b815260206004820152600e60248201526d1d995c9a599e4e8819985a5b195960921b6044820152606490fd5b60008091604051610e6e81610bdf6020820194602086526040808401526060830190610177565b51906001600160981b015afa610e82610865565b9015610e8b5790565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fdfe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acea26469706673582212208f2083bcb5829a4b928dccb1429711d04d98d3340e43bb24bd6a40896c89eaa564736f6c63430008160033360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00a2646970667358221220cc74953dcf20e8b7d5facfd5b500de2b792294cfd013b5270b8308de0c561ce564736f6c63430008160033";

type TestAccountConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: TestAccountConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class TestAccount__factory extends ContractFactory {
  constructor(...args: TestAccountConstructorParams) {
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
      TestAccount & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): TestAccount__factory {
    return super.connect(runner) as TestAccount__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TestAccountInterface {
    return new Interface(_abi) as TestAccountInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): TestAccount {
    return new Contract(address, _abi, runner) as unknown as TestAccount;
  }
}
