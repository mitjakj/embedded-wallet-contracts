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
  "0x6080806040523461008557613c1b8181016001600160401b0381118382101761006f578291610203833903906000f0801561006357600080546001600160a01b0319166001600160a01b0392909216919091179055604051610178908161008b8239f35b6040513d6000823e3d90fd5b634e487b7160e01b600052604160045260246000fd5b600080fdfe608080604052600436101561001357600080fd5b600090813560e01c63b8b1d0cb1461002a57600080fd5b3461013e578160031936011261013e5760018060a01b03906020816064818686815416631cc42c0760e31b83523360048401528160248401528160448401525af19081156101335783916100aa575b506020907fbe2f3d28fdeb5839123d65fd47ec2f5915c715d2b527b9e229123706fdecfc859260405191168152a180f35b905060203d60201161012c575b601f8101601f1916820167ffffffffffffffff8111838210176101185760209183916040528101031261011457518181168103610114577fbe2f3d28fdeb5839123d65fd47ec2f5915c715d2b527b9e229123706fdecfc85610079565b8280fd5b634e487b7160e01b85526041600452602485fd5b503d6100b7565b6040513d85823e3d90fd5b5080fdfea264697066735822122057270031a6291b983bd6906346600fe20b3eabf568ab9873a53a3ae52c44221564736f6c6343000816003360a080604052346100cc57306080527ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a009081549060ff8260401c166100bd57506001600160401b036002600160401b031982821601610078575b604051613b4990816100d2823960805181818161033001526104680152f35b6001600160401b031990911681179091556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1388080610059565b63f92ee8a960e01b8152600490fd5b600080fdfe6080604052600436101561001257600080fd5b60003560e01c806301ffc9a7146100d7578063248a9ca3146100d25780632f2ff15d146100cd57806336568abe146100c85780634f1ef286146100c357806352d1902d146100be5780638129fc1c146100b957806391d14854146100b4578063a217fddf146100af578063ad3cb1cc146100aa578063d547741f146100a55763e6216038146100a057600080fd5b610728565b6106dc565b61065f565b610643565b6105e4565b6104c0565b610455565b6102b8565b6101e8565b61019a565b610132565b3461012d57602036600319011261012d5760043563ffffffff60e01b811680910361012d57602090637965db0b60e01b811490811561011c575b506040519015158152f35b6301ffc9a760e01b14905038610111565b600080fd5b3461012d57602036600319011261012d57600435600052600080516020613ad48339815191526020526020600160406000200154604051908152f35b602435906001600160a01b038216820361012d57565b600435906001600160a01b038216820361012d57565b3461012d57604036600319011261012d576101e66004356101b961016e565b9080600052600080516020613ad48339815191526020526101e16001604060002001546109a8565b6109fa565b005b3461012d57604036600319011261012d5761020161016e565b336001600160a01b0382160361021d576101e690600435610a9b565b60405163334bd91960e11b8152600490fd5b634e487b7160e01b600052604160045260246000fd5b67ffffffffffffffff811161025957604052565b61022f565b6040810190811067ffffffffffffffff82111761025957604052565b90601f8019910116810190811067ffffffffffffffff82111761025957604052565b67ffffffffffffffff811161025957601f01601f191660200190565b60408060031936011261012d576102cd610184565b60243567ffffffffffffffff811161012d573660238201121561012d5780600401356102f88161029c565b916103058551938461027a565b818352366024838301011161012d578160009260246020930183860137830101526001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000811630811490811561042e575b5061041d57602060049161036e610950565b85516352d1902d60e01b8152928391829087165afa600091816103ec575b506103b1578351634c9c8ce360e01b81526001600160a01b0384166004820152602490fd5b600080516020613ab483398151915281939293036103d3576101e68383610b9a565b8351632a87526960e21b81526004810191909152602490fd5b61040f91925060203d602011610416575b610407818361027a565b810190610b33565b903861038c565b503d6103fd565b835163703e46dd60e11b8152600490fd5b905081600080516020613ab4833981519152541614153861035c565b600091031261012d57565b3461012d57600036600319011261012d577f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031630036104ae576020604051600080516020613ab48339815191528152f35b60405163703e46dd60e11b8152600490fd5b600036600319011261012d57600080516020613af48339815191525467ffffffffffffffff60ff8260401c16159116801590816105dc575b60011490816105d2575b1590816105c9575b506105b757600080516020613af4833981519152805467ffffffffffffffff191660011790558061058d575b61053e61077b565b61054457005b600080516020613af4833981519152805460ff60401b19169055604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d290602090a1005b600080516020613af4833981519152805460ff60401b191668010000000000000000179055610536565b60405163f92ee8a960e01b8152600490fd5b9050153861050a565b303b159150610502565b8291506104f8565b3461012d57604036600319011261012d57602060ff61063761060461016e565b600435600052600080516020613ad4833981519152845260406000209060018060a01b0316600052602052604060002090565b54166040519015158152f35b3461012d57600036600319011261012d57602060405160008152f35b3461012d57600036600319011261012d57604080519061067e8261025e565b60058252602090640352e302e360dc1b6020840152604051916020835283519182602085015260005b8381106106c95784604081866000838284010152601f80199101168101030190f35b85810183015185820183015282016106a7565b3461012d57604036600319011261012d576101e66004356106fb61016e565b9080600052600080516020613ad48339815191526020526107236001604060002001546109a8565b610a9b565b3461012d57606036600319011261012d57610741610184565b602435600381101561012d5760209161075d916044359161084a565b6040516001600160a01b039091168152f35b6040513d6000823e3d90fd5b610783610c41565b61078b610c41565b60405167ffffffffffffffff90611e7f80820183811183821017610259578291610d16833903906000f080156108255760018060a01b03166bffffffffffffffffffffffff60a01b600054161760005560405190610f1f908183019083821090821117610259578291612b95833903906000f0801561082557600180546001600160a01b0319166001600160a01b03909216919091179055565b61076f565b6003111561083457565b634e487b7160e01b600052602160045260246000fd5b91906108558161082a565b806108e5575060005461088990610878908190610884906001600160a01b031682565b6001600160a01b031690565b610b42565b91823b1561012d57604051630b302c9560e21b81526001600160a01b03919091166004820152602481019190915260008160448183865af18015610825576108cf575090565b806108dc6108e292610245565b8061044a565b90565b806108f160019261082a565b036109135760015461088990610878908190610884906001600160a01b031682565b60405162461bcd60e51b8152602060048201526015602482015274416374696f6e206e6f7420737570706f727465642160581b6044820152606490fd5b3360009081527fb7db2dd08fcb62d0c9e08c51941cae53c267786a0b75803fb7960902fc8ef97d602052604090205460ff161561098957565b60405163e2517d3f60e01b815233600482015260006024820152604490fd5b6000818152600080516020613ad48339815191526020908152604080832033845290915290205460ff16156109da5750565b60405163e2517d3f60e01b81523360048201526024810191909152604490fd5b6000818152600080516020613ad4833981519152602081815260408084206001600160a01b038716855290915282205491929160ff16610a9457818352602090815260408084206001600160a01b038616600090815292529020805460ff1916600117905533926001600160a01b0316917f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d9080a4600190565b5050905090565b6000818152600080516020613ad4833981519152602081815260408084206001600160a01b038716855290915282205491929160ff1615610a9457818352602090815260408084206001600160a01b038616600090815292529020805460ff1916905533926001600160a01b0316917ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b9080a4600190565b9081602091031261012d575190565b604051733d602d80600a3d3981f3363d3d373d3d3d363d7360601b815260609190911b6bffffffffffffffffffffffff191660148201526e5af43d82803e903d91602b57fd5bf360881b60288201526037906000f090565b90813b15610c2057600080516020613ab483398151915280546001600160a01b0319166001600160a01b0384169081179091557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a2805115610c0557610c0291610c70565b50565b505034610c0e57565b60405163b398979f60e01b8152600490fd5b604051634c9c8ce360e01b81526001600160a01b0383166004820152602490fd5b60ff600080516020613af48339815191525460401c1615610c5e57565b604051631afcd79f60e31b8152600490fd5b6000806108e293602081519101845af43d15610cae573d91610c918361029c565b92610c9f604051948561027a565b83523d6000602085013e610cb2565b6060915b90610cd95750805115610cc757805190602001fd5b60405163d6bda27560e01b8152600490fd5b81511580610d0c575b610cea575090565b604051639996b31560e01b81526001600160a01b039091166004820152602490fd5b50803b15610ce256fe6080806040523461002357600160ff196000541617600055611e5690816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146101075780631b8b921d146101025780631d647605146100fd578063260558a0146100f85780632cc0b254146100f357806337022e98146100ee5780635ced058e146100e95780637d1f3b6f146100e457806382c947b7146100df57806388196f68146100da578063a9059cbb146100d5578063b429afeb146100d0578063d04731d4146100cb578063e341eaa4146100c65763fc9ffe02146100c157600080fd5b61087a565b610782565b6106d6565b610697565b61062a565b6105aa565b61057e565b6104f5565b6104ce565b610465565b6103c3565b61037a565b610335565b6102c3565b610168565b60005b83811061011f5750506000910152565b818101518382015260200161010f565b906020916101488151809281855285808601910161010c565b601f01601f1916010190565b90602061016592818152019061012f565b90565b346102385760031960403682011261023857600435602435916001600160401b0383116102385760e0908336030112610238573360005260016020526101ba600160ff6040600020541615151461090f565b60025481106101c88161094e565b156102335761022f91610223916002600052600080516020611e018339815191520154906101f78215156109a4565b816000526003602052610214604060002054913690600401610b0e565b916001600160a01b0316610cc9565b60405191829182610154565b0390f35b61098e565b600080fd5b600435906001600160a01b038216820361023857565b35906001600160a01b038216820361023857565b6040600319820112610238576004356001600160a01b038116810361023857916024356001600160401b039283821161023857806023830112156102385781600401359384116102385760248483010111610238576024019190565b34610238576102d136610267565b9160009283809333825260016020526102f5600160ff60408520541615151461090f565b826040519384928337810182815203925af161030f610b93565b901561032d5761022f9060405191829160208352602083019061012f565b602081519101fd5b3461023857602036600319011261023857336000526001602052610365600160ff6040600020541615151461090f565b6020610372600435610e04565b604051908152f35b346102385760008061038b36610267565b9033845260016020526103a9600160ff60408720541615151461090f565b816040519283928337810184815203915afa61030f610b93565b34610238576040366003190112610238576103dc61023d565b60ff6000541661042b5760018060a01b0316600052600160205261040b6040600020600160ff19825416179055565b610416602435610e04565b50610429600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b346102385760403660031901126102385761047e61023d565b6024358015158091036102385760009133835260016020526104ab600160ff60408620541615151461090f565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b34610238576020366003190112610238576040516004356001600160a01b03168152602090f35b3461023857602036600319011261023857600435336000526001602052610528600160ff6040600020541615151461090f565b60025481106105368161094e565b15610233576002600052600080516020611e01833981519152015461055c8115156109a4565b600052600360205261022f604060002054604051918291829190602083019252565b346102385760203660031901126102385760206001600160a01b036105a161023d565b16604051908152f35b34610238576020366003190112610238576004353360005260016020526105dd600160ff6040600020541615151461090f565b60025481106105eb8161094e565b156102335761022f906002600052600080516020611e0183398151915201546106158115156109a4565b60026000526040519081529081906020820190565b346102385760403660031901126102385761064361023d565b602435906000808080948194338352600160205261066c600160ff60408620541615151461090f565b8290821561068d575b6001600160a01b031690f1156106885780f35b610bc3565b6108fc9150610675565b34610238576020366003190112610238576001600160a01b036106b861023d565b166000526001602052602060ff604060002054166040519015158152f35b3461023857602036600319011261023857600435600090338252600160205261070a600160ff60408520541615151461090f565b60025481106107188161094e565b15610233576002825280600080516020611e0183398151915201908154906107418215156109a4565b818452600360205283604081205560025411156102335760028352908290556001600160a01b03166000908152600160205260409020805460ff1916905580f35b346102385760403660031901126102385760043561079e610bcf565b503360005260016020526107be600160ff6040600020541615151461090f565b60025481106107cc8161094e565b156102335761081a61022f916002600052600080516020611e0183398151915201546107f98115156109a4565b600081815260036020526040902054602435916001600160a01b0316610f18565b60408051825181526020808401519082015291810151908201529081906060820190565b602090602060408183019282815285518094520193019160005b828110610866575050505090565b835185529381019392810192600101610858565b346102385760008060031936011261090c57338152600160209160016020526108ae600160ff60408420541615151461090f565b6040519182602060025491828152019460028452600080516020611e0183398151915293905b8282106108f75761022f866108eb818a0382610a68565b6040519182918261083e565b845487529586019593830193908301906108d4565b80fd5b1561091657565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b1561095557565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b156109ab57565b60405162461bcd60e51b815260206004820152600e60248201526d15d85b1b195d081c995b5bdd995960921b6044820152606490fd5b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b03821117610a1257604052565b6109e1565b60e081019081106001600160401b03821117610a1257604052565b604081019081106001600160401b03821117610a1257604052565b602081019081106001600160401b03821117610a1257604052565b90601f801991011681019081106001600160401b03821117610a1257604052565b60405190610a9682610a17565b565b35906001600160401b038216820361023857565b6001600160401b038111610a1257601f01601f191660200190565b81601f8201121561023857803590610ade82610aac565b92610aec6040519485610a68565b8284526020838301011161023857816000926020809301838601378301015290565b919060e08382031261023857610b22610a89565b92610b2c81610a98565b845260208101356020850152610b4460408201610a98565b6040850152610b5560608201610253565b60608501526080810135608085015260a08101356001600160401b0381116102385760c092610b85918301610ac7565b60a0850152013560c0830152565b3d15610bbe573d90610ba482610aac565b91610bb26040519384610a68565b82523d6000602084013e565b606090565b6040513d6000823e3d90fd5b60405190610bdc826109f7565b60006040838281528260208201520152565b634e487b7160e01b600052601160045260246000fd5b6401000003d01990810391908211610c1857565b610bee565b600019810191908211610c1857565b6020039060208211610c1857565b91908203918211610c1857565b600381901b91906001600160fd1b03811603610c1857565b908160081b918083046101001490151715610c1857565b9060238201809211610c1857565b6004019081600411610c1857565b9060018201809211610c1857565b9060048201809211610c1857565b9060028201809211610c1857565b91908201809211610c1857565b610d3990929192610cd8610bcf565b5060c0830193610d06855160405190610cf0826109f7565b6000825260006020830152604082015285611122565b604051610d3060208281610d23818301968781519384920161010c565b8101038084520182610a68565b51902091610f18565b9060408201805193601a198501948511610c1857518060011b9080820460021490151715610c1857610d71610d769161016596610cbc565b610c76565b9052611122565b15610d8457565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b60025468010000000000000000811015610a12576001810180600255811015610233576002600052600080516020611e018339815191520155565b60646002541015610ed35780610e915750610e84610165610e236114e0565b92905b6001600160a01b0381166000818152600360205260409020909490610e4c905415610d7d565b610e5585610dc9565b610e69856000526003602052604060002090565b556001600160a01b0316600090815260016020526040902090565b805460ff19166001179055565b610165610e84610ece610ec8604051610ec381610eb5886020830160209181520190565b03601f198101835282610a68565b6112cb565b506113af565b610e26565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b90929192610f24610bcf565b5060409060008083610f91610fc0825160209687820152868152610f4781610a32565b8351908b88830152878252610f5b82610a32565b610fb48551610f6981610a4d565b878152610fa4875196879460808d87019a610f848c60049052565b87015260a086019061012f565b601f19958686830301606087015261012f565b908484830301608085015261012f565b03908101835282610a68565b51906006600160981b015afa91610fd5610b93565b9215610ff257505090610fea610a96926115d3565b9384916117c6565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b906110376020928281519485920161010c565b0190565b6040519061014082018281106001600160401b03821117610a1257604052600982528160005b610120811061106e575050565b806060602080938501015201611061565b8051156102335760200190565b8051600110156102335760400190565b8051600210156102335760600190565b8051600310156102335760800190565b8051600410156102335760a00190565b8051600510156102335760c00190565b8051600610156102335760e00190565b805160071015610233576101000190565b805160081015610233576101200190565b80518210156102335760209160051b010190565b61127060206101659361121660a061113861103b565b9561116161115c61115083516001600160401b031690565b6001600160401b031690565b6118a1565b61116a8861107f565b526111748761107f565b50611181858201516118a1565b61118a8861108c565b526111948761108c565b506111af61115c61115060408401516001600160401b031690565b6111b88861109c565b526111c28761109c565b5060608101516111da906001600160a01b0316611948565b6111e3886110ac565b526111ed876110ac565b506111fb60808201516118a1565b611204886110bc565b5261120e876110bc565b500151611975565b61121f856110cc565b52611229846110cc565b5061123760408201516118a1565b611240856110dc565b5261124a846110dc565b5061125581516118a1565b61125e856110ec565b52611268846110ec565b5001516118a1565b611279826110fd565b52611283816110fd565b50611ae2565b81601f8201121561023857805161129f81610aac565b926112ad6040519485610a68565b8184526020828401011161023857610165916020808501910161010c565b9060409081516020906112f281610eb584820197600489528780840152606083019061012f565b51600094859182916005600160981b015afa9061130d610b93565b911561136c57815182019184818385019403126113685781810151906001600160401b039182811161136457848461134792840101611289565b9581015191821161136057610165949596500101611289565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fd5b60218151036114ab57602181015190805115610233576020015160f81c60006002821415806114a0575b61148e57806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c080830191909152815261143381610a17565b519060055afa91611442610b93565b921561147c5761146761146161145a610165956114bd565b9384610cbc565b60011690565b15611c0b579061147690610c04565b90611c0b565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b5060038214156113d9565b604051636446a2c560e11b8152600490fd5b6020815191015190602081106114d1575090565b6000199060200360031b1b1690565b6000806040516114ef81610a4d565b81815260405161151581610eb5602082019460208652604080840152606083019061012f565b51906001600160981b015afa611529610b93565b901561154757611544610ec861153e836114bd565b926112cb565b91565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b8051600210156102335760220190565b8051600110156102335760210190565b8051600310156102335760230190565b8051600410156102335760240190565b908151811015610233570160200190565b906115dc610bcf565b91600881511061178e576001600160f81b0319600360fc1b8161160f6116018561107f565b516001600160f81b03191690565b160361178e57600160f91b808261162861160186611582565b160361178e5761164c61164661164061160186611592565b60f81c90565b60ff1690565b9161165f611646611640611601876115a2565b926021841161178e5761167184610c84565b9061168d61164661164061160161168786610c92565b8a6115c2565b936021851161178e576116b36116a6611601858a6115c2565b6001600160f81b03191690565b0361178e57806116cb6116c68688610cbc565b610ca0565b0361178e576116db865191610cae565b0361178e576116e990610cae565b90600490602185146117a0575b6021841461175b575b50906020809286010151940101519160208110611744575b506020811061172c575b509083526020830152565b61173861173d91610c2c565b610c47565b1c38611721565b61173861175391949294610c2c565b1c9138611717565b61176b61160184889694966115c2565b1661178e57602061178561177f8294610c92565b92610c1d565b939192506116ff565b6040516386cd05c560e01b8152600490fd5b809491506117b0611601876115b2565b1661178e576117c0600591610c1d565b936116f6565b916040810190601b825280519260208201906020611802835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa156106885784516001600160a01b039687169616869003611835575b505050505050565b6118678593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa1561068857516001600160a01b03160361188f5738808080808061182d565b604051634532600d60e01b8152600490fd5b906040516118bc81610eb56020956020830160209181520190565b6000926000905b808210611924575b506118dd6118d882610c2c565b611c6a565b9160005b8351811015611916576001906119036116016118fc86611c9c565b95856115c2565b871a61190f82876115c2565b53016118e1565b505050610165919250611975565b906119356116a661160183866115c2565b61194257600101906118c3565b906118cb565b61016590604051906bffffffffffffffffffffffff199060601b1660208201526014815261197581610a32565b90600091805192600193600181149081611aca575b501561199557509150565b81519360388510156119f9575092610eb5610165926119f394956119d66119c660ff6119bf611c38565b9616611cdd565b60f81b6001600160f81b03191690565b901a6119e18461107f565b535b6040519485936020850190611024565b90611024565b9091908290600190805b611a9a575b5050611a166118d882610c92565b92611a2e6119c6611a2960ff8516611cdd565b611ccb565b811a611a398561107f565b5360015b82811115611a5b575050506119f392935090610eb5610165926119e3565b80611a836119c6611646611646611a7d611a78611a95978a610c3a565b611d01565b8c611cab565b831a611a8f82886115c2565b53611c9c565b611a3d565b9091611aa68388611cab565b15611ac457611ab7611abd91611c9c565b92610c5f565b9080611a03565b91611a08565b905015610233576080602083015160f81c103861198a565b611aeb90611d10565b805160006038821015611b5c5750602061016591611b166119c660ff611b0f611c38565b9316611cef565b60001a611b228261107f565b535b6040519381611b3c869351809286808701910161010c565b8201611b508251809386808501910161010c565b01038084520182610a68565b909260019290915b611b6e8486611cab565b15611b8b57611b7f611b8591611c9c565b93610c5f565b92611b64565b909250929092611b9d6118d882610c92565b91611bb06119c6611a2960ff8516611cef565b60001a611bbc8461107f565b5360015b82811115611bd657505050602061016591611b24565b80611bf96119c6611646611646611bf3611a78611c06978a610c3a565b87611cab565b60001a611a8f82876115c2565b611bc0565b6040519160208301918252604083015260408252611c28826109f7565b905190206001600160a01b031690565b60405190611c4582610a32565b6001825260203681840137565b604051611c5e81610a4d565b60008152906000368137565b90611c7482610aac565b611c816040519182610a68565b8281528092611c92601f1991610aac565b0190602036910137565b6000198114610c185760010190565b8115611cb5570490565b634e487b7160e01b600052601260045260246000fd5b60ff60379116019060ff8211610c1857565b60ff60809116019060ff8211610c1857565b60ff60c09116019060ff8211610c1857565b601f8111610c18576101000a90565b805115611d9f5790600091825b8151841015611d4657611d3e600191611d36868561110e565b515190610cbc565b930192611d1d565b611d5291929350611c6a565b906020808301936000945b8351861015611d9757611d8f600191611d85611d79898861110e565b51868151910183611da8565b611d36888761110e565b950194611d5d565b509350505090565b50610165611c52565b92905b602093848410611de05781518152848101809111610c1857938101809111610c185791601f198101908111610c185791611dab565b9290919350600019906020036101000a019081199051169082511617905256fe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acea26469706673582212201ab761084908b06fbd94e5cf0dfc3a3bf40c1ef27d4054d3ec2bf7c42cdf05fb64736f6c634300081600336080806040523461002357600160ff196000541617600055610ef690816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c80631b8b921d146100d75780631d647605146100d2578063260558a0146100cd5780632cc0b254146100c857806337022e98146100c35780637d1f3b6f146100be57806388196f68146100b95780639b3d270a146100b4578063a9059cbb146100af578063b429afeb146100aa578063d04731d4146100a55763fc9ffe02146100a057600080fd5b610747565b610685565b610646565b6105d2565b61054d565b610458565b6103ca565b610360565b6102b4565b61026b565b610226565b6101b0565b600435906001600160a01b03821682036100f257565b600080fd5b60406003198201126100f2576004356001600160a01b03811681036100f2579160243567ffffffffffffffff928382116100f257806023830112156100f25781600401359384116100f257602484830101116100f2576024019190565b60005b8381106101675750506000910152565b8181015183820152602001610157565b9060209161019081518092818552858086019101610154565b601f01601f1916010190565b9060206101ad928181520190610177565b90565b346100f2576101be366100f7565b9160009283809333825260016020526101e2600160ff6040852054161515146107dc565b826040519384928337810182815203925af16101fc61083f565b901561021e5761021a90604051918291602083526020830190610177565b0390f35b602081519101fd5b346100f25760203660031901126100f257336000526001602052610256600160ff604060002054161515146107dc565b6020610263600435610b20565b604051908152f35b346100f25760008061027c366100f7565b90338452600160205261029a600160ff6040872054161515146107dc565b816040519283928337810184815203915afa6101fc61083f565b346100f25760403660031901126100f2576102cd6100dc565b60ff6000541661031c5760018060a01b031660005260016020526102fc6040600020600160ff19825416179055565b610307602435610b20565b5061031a600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b801515036100f257565b346100f25760403660031901126100f2576103796100dc565b60243561038581610356565b60009133835260016020526103a5600160ff6040862054161515146107dc565b60018060a01b031682526001602052604082209060ff80198354169115151617905580f35b346100f25760203660031901126100f2576004353360005260016020526103fd600160ff604060002054161515146107dc565b600254811061040b8161086f565b15610453576002600052600080516020610ea183398151915201546104318115156108c5565b600052600360205261021a604060002054604051918291829190602083019252565b6108af565b346100f25760203660031901126100f25760043533600052600160205261048b600160ff604060002054161515146107dc565b60025481106104998161086f565b156104535761021a906002600052600080516020610ea183398151915201546104c38115156108c5565b60026000526040519081529081906020820190565b634e487b7160e01b600052604160045260246000fd5b6040810190811067ffffffffffffffff82111761050a57604052565b6104d8565b90601f8019910116810190811067ffffffffffffffff82111761050a57604052565b67ffffffffffffffff811161050a57601f01601f191660200190565b346100f25760403660031901126100f25760243567ffffffffffffffff81116100f257366023820112156100f25780600401359061058a82610531565b610597604051918261050f565b82815236602484840101116100f257600060208461021a9560246105c696018386013783010152600435610902565b6040519182918261019c565b346100f25760403660031901126100f2576105eb6100dc565b6024359060008080809481943383526001602052610614600160ff6040862054161515146107dc565b8290821561063c575b6001600160a01b031690f1156106305780f35b604051903d90823e3d90fd5b6108fc915061061d565b346100f25760203660031901126100f2576001600160a01b036106676100dc565b166000526001602052602060ff604060002054166040519015158152f35b346100f25760203660031901126100f25760043560009033825260016020526106b9600160ff6040852054161515146107dc565b60025481106106c78161086f565b15610453576002825280600080516020610ea1833981519152019081546106ef8115156108c5565b8352600360205282604081205560025411156104535781905580f35b602090602060408183019282815285518094520193019160005b828110610733575050505090565b835185529381019392810192600101610725565b346100f2576000806003193601126107d9573381526001602091600160205261077b600160ff6040842054161515146107dc565b6040519182602060025491828152019460028452600080516020610ea183398151915293905b8282106107c45761021a866107b8818a038261050f565b6040519182918261070b565b845487529586019593830193908301906107a1565b80fd5b156107e357565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b604051906020820182811067ffffffffffffffff82111761050a5760405260008252565b3d1561086a573d9061085082610531565b9161085e604051938461050f565b82523d6000602084013e565b606090565b1561087657565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b156108cc57565b60405162461bcd60e51b815260206004820152600e60248201526d15d85b1b195d081c995b5bdd995960921b6044820152606490fd5b90600091338352602060018152604093610926600160ff87842054161515146107dc565b60025483106109348161086f565b15610453576109ea9260028252600080516020610ea1833981519152015461095d8115156108c5565b81526003825280856109bb6109878284205483519087820152868152610982816104ee565b610c54565b610992979197610a51565b906109de6109ce865195869360808c8601996109ae8b60069052565b86015260a0850190610177565b601f199485858303016060860152610177565b838382030160808401528b610177565b0390810183528261050f565b51906006600160981b015afa936109ff61083f565b9415610a1f575050610a1b918391610a15610a51565b90610d4e565b5090565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b60405190610a5e826104ee565b600982526873756273747261746560b81b6020830152565b602081519101519060208110610a8a575090565b6000199060200360031b1b1690565b15610aa057565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b6002546801000000000000000081101561050a576001810180600255811015610453576002600052600080516020610ea18339815191520155565b60646002541015610bcd5780610b9b5750610b41610b3c61081b565b610e21565b610b5c610b56610b5083610c54565b50610a76565b91610a76565b610b7a610b73836000526003602052604060002090565b5415610a99565b610b8382610ae5565b610b97826000526003602052604060002090565b5590565b610bc7610b5060405161098281610bb9866020830160209181520190565b03601f19810183528261050f565b90610b5c565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b81601f820112156100f2578051610c2881610531565b92610c36604051948561050f565b818452602082840101116100f2576101ad9160208085019101610154565b906040908151602090610c7b81610bb9848201976006895287808401526060830190610177565b51600094859182916005600160981b015afa90610c9661083f565b9115610cf65781518201918481838501940312610cf257818101519067ffffffffffffffff91828111610cee578484610cd192840101610c12565b95810151918211610cea576101ad949596500101610c12565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fd5b908160209103126100f257516101ad81610356565b90610dbe610dae91600095946109de8796604051958693610d9e610d8b602087019a610d7a8c60069052565b60a0604089015260c0880190610177565b601f199788888303016060890152610177565b9086868303016080870152610177565b90848483030160a0850152610177565b51906007600160981b015afa610dd261083f565b9015610deb57806020806101ad93518301019101610d39565b60405162461bcd60e51b815260206004820152600e60248201526d1d995c9a599e4e8819985a5b195960921b6044820152606490fd5b60008091604051610e4881610bb96020820194602086526040808401526060830190610177565b51906001600160981b015afa610e5c61083f565b9015610e655790565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fdfe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acea264697066735822122080366584b0b41588853f03bbe0d006dc10c55ed1e68c91bfe32a0167aa380b0664736f6c63430008160033360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00a26469706673582212204f647cd71e3c325dc9a401f30ec32ecc6492b8883c2a1bb44bb6620188a1f47864736f6c63430008160033";

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
