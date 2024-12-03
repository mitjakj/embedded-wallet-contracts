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
  AccountFactory,
  AccountFactoryInterface,
} from "../../../contracts/Account.sol/AccountFactory";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
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

const _bytecode =
  "0x60808060405234610085576120c58181016001600160401b0381118382101761006f578291610351833903906000f0801561006357600080546001600160a01b0319166001600160a01b03929092169190911790556040516102c6908161008b8239f35b6040513d6000823e3d90fd5b634e487b7160e01b600052604160045260246000fd5b600080fdfe6080604052600436101561001257600080fd5b6000803560e01c633e1e53b61461002857600080fd5b34610101576080366003190112610101576004356001600160a01b03811681036100fd576024359060038210156100f9576064359167ffffffffffffffff8084116100f557366023850112156100f55783600401359081116100f0576040519361009c601f8301601f19166020018661012e565b81855236602483830101116100ec57946020826100ce9695949360246100e8990183880137850101526044359161016c565b6040516001600160a01b0390911681529081906020820190565b0390f35b8580fd5b610104565b8480fd5b8280fd5b5080fd5b80fd5b634e487b7160e01b600052604160045260246000fd5b67ffffffffffffffff81116100f057604052565b90601f8019910116810190811067ffffffffffffffff8211176100f057604052565b600091031261015b57565b600080fd5b6040513d6000823e3d90fd5b60008054604051733d602d80600a3d3981f3363d3d373d3d3d363d7360601b815260609190911b6bffffffffffffffffffffffff191660148201526e5af43d82803e903d91602b57fd5bf360881b60288201526001600160a01b0396959294919390879060379086f01696873b156100f557604051630b60dfb960e31b815295166004860152600381101561027c5760248501526044840152608060648401528051608484018190528391835b82811061026457505081818460a4809484010152601f8019910116810103018183875af1801561025f5761024a5750565b8061025761025d9261011a565b80610150565b565b610160565b602082820181015160a4888401015286945001610219565b634e487b7160e01b84526021600452602484fdfea26469706673582212209dcfa4628f13c26f5e6f381fbdc337223b9fa753ffa342284a547fd9f780323f64736f6c634300081500336080806040523461002357600160ff19600054161760005561209c90816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146100d75780631b8b921d146100d2578063260558a0146100cd57806337022e98146100c85780635b06fdc8146100c35780637d1f3b6f146100be57806388196f68146100b9578063a9059cbb146100b4578063b429afeb146100af578063becd532d146100aa578063e341eaa4146100a55763fc9ffe02146100a057600080fd5b6109d5565b61086b565b6107e5565b6107a6565b610739565b6106ea565b610671565b610577565b6103d9565b610390565b61031e565b610138565b60005b8381106100ef5750506000910152565b81810151838201526020016100df565b90602091610118815180928185528580860191016100dc565b601f01601f1916010190565b9060206101359281815201906100ff565b90565b346102935760031960403682011261029357600435906024356001600160401b03918282116102935760e0908236030112610293576101ab6101a56000943386526001602052610193600160ff604089205416151514610a7e565b6101a06002548210610abd565b610b13565b50610b98565b60208101805191516001600160a01b039283169392909190600383101561028e576101f492875260036020526040872091511660018060a01b0316600052602052604060002090565b54926101fe6104f9565b9461020b83600401610c92565b86526024830135602087015261022360448401610c92565b6040870152610234606484016102ae565b60608701526084830135608087015260a483013591821161028b5761028761027b87878760c48861026a368a8301600401610530565b60a0860152013560c0840152610d81565b60405191829182610124565b0390f35b80fd5b61092b565b600080fd5b600435906001600160a01b038216820361029357565b35906001600160a01b038216820361029357565b6040600319820112610293576004356001600160a01b038116810361029357916024356001600160401b039283821161029357806023830112156102935781600401359384116102935760248483010111610293576024019190565b346102935761032c366102c2565b916000928380933382526001602052610350600160ff604085205416151514610a7e565b826040519384928337810182815203925af161036a611a5d565b901561038857610287906040519182916020835260208301906100ff565b602081519101fd5b34610293576000806103a1366102c2565b9033845260016020526103bf600160ff604087205416151514610a7e565b816040519283928337810184815203915afa61036a611a5d565b34610293576040366003190112610293576103f2610298565b60243580151580910361029357600091338352600160205261041f600160ff604086205416151514610a7e565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b60243590600382101561029357565b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b0382111761048257604052565b610451565b60e081019081106001600160401b0382111761048257604052565b604081019081106001600160401b0382111761048257604052565b602081019081106001600160401b0382111761048257604052565b90601f801991011681019081106001600160401b0382111761048257604052565b6040519061050682610487565b565b6040519061050682610467565b6001600160401b03811161048257601f01601f191660200190565b81601f820112156102935780359061054782610515565b9261055560405194856104d8565b8284526020838301011161029357816000926020809301838601378301015290565b3461029357608036600319011261029357610590610298565b610598610442565b6064356001600160401b038111610293576105b7903690600401610530565b9160ff600054166106375761062392610616926105fc9260018060a01b031660005260016020526105f36040600020600160ff19825416179055565b60443590611c8e565b6001600160a01b0316600090815260016020526040902090565b805460ff19166001179055565b610635600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b34610293576020366003190112610293573360005260016020526106a1600160ff60406000205416151514610a7e565b6106af6101a5600435610b13565b8051600381101561028e576000908152600360209081526040808320938201516001600160a01b031683529281529082902054915191825290f35b346102935760203660031901126102935760206107216004353360005260018352610193600160ff60406000205416151514610a7e565b505460405160089190911c6001600160a01b03168152f35b3461029357604036600319011261029357610752610298565b602435906000808080948194338352600160205261077b600160ff604086205416151514610a7e565b8290821561079c575b6001600160a01b031690f1156107975780f35b61142f565b6108fc9150610784565b34610293576020366003190112610293576001600160a01b036107c7610298565b166000526001602052602060ff604060002054166040519015158152f35b34610293576060366003190112610293576004356003811015610293576044356001600160401b0381116102935761028791610828610851923690600401610530565b90336000526001602052610848600160ff60406000205416151514610a7e565b60243590611c8e565b6040516001600160a01b0390911681529081906020820190565b34610293576040366003190112610293576108ad6101a560043561088d61109a565b50336000526001602052610193600160ff60406000205416151514610a7e565b6020810180519151916001600160a01b0391908216600384101561028e576109006109079361028795600052600360205260406000209060243594511660018060a01b0316600052602052604060002090565b54906110d0565b60408051825181526020808401519082015291810151908201529081906060820190565b634e487b7160e01b600052602160045260246000fd5b60208082019080835283518092526040928381019382818560051b8401019601946000925b858410610977575050505050505090565b90919293949596603f198282030183528751606090805190600382101561028e57838993886109c493869560019852878060a01b03868201511686850152015191818a82015201906100ff565b990193019401929195949390610966565b346102935760008060031936011261028b57338152600190602090828252610a078360ff604084205416151514610a7e565b6002805491610a1583610e35565b93610a2360405195866104d8565b8385528282527f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace8186015b858410610a6357604051806102878982610941565b84838992610a7085610b98565b815201920193019290610a4e565b15610a8557565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b15610ac457565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b600254811015610b4d57600260005260011b7f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace0190600090565b610afd565b600382101561028e5752565b90600182811c92168015610b8e575b6020831014610b7857565b634e487b7160e01b600052602260045260246000fd5b91607f1691610b6d565b9060405191610ba683610467565b82815491610bb760ff841683610b52565b60209260018060a01b039060081c1683830152600180910190604051938492600092815491610be583610b5e565b80875292828116908115610c585750600114610c13575b5050505060409291610c0f9103846104d8565b0152565b60009081528381209695945091905b818310610c4057509394509192509082010181610c0f604038610bfc565b86548884018501529586019587945091830191610c22565b60ff191685880152505050151560051b830101905081610c0f604038610bfc565b600381101561028e576000526003602052604060002090565b35906001600160401b038216820361029357565b634e487b7160e01b600052601160045260246000fd5b600019810191908211610ccb57565b610ca6565b6020039060208211610ccb57565b6401000003d01990810391908211610ccb57565b91908203918211610ccb57565b600381901b91906001600160fd1b03811603610ccb57565b908160081b918083046101001490151715610ccb57565b9060238201809211610ccb57565b6004019081600411610ccb57565b9060018201809211610ccb57565b9060048201809211610ccb57565b9060028201809211610ccb57565b91908201809211610ccb57565b610df190929192610d9061109a565b5060c0830193610dbe855160405190610da882610467565b6000825260006020830152604082015285610f33565b604051610de860208281610ddb81830196878151938492016100dc565b81010380845201826104d8565b519020916110d0565b9060408201805193601a198501948511610ccb57518060011b9080820460021490151715610ccb57610e29610e2e9161013596610d74565b610d2e565b9052610f33565b6001600160401b0381116104825760051b60200190565b6040519061014082018281106001600160401b0382111761048257604052600982528160005b6101208110610e7f575050565b806060602080938501015201610e72565b805115610b4d5760200190565b805160011015610b4d5760400190565b805160021015610b4d5760600190565b805160031015610b4d5760800190565b805160041015610b4d5760a00190565b805160051015610b4d5760c00190565b805160061015610b4d5760e00190565b805160071015610b4d576101000190565b805160081015610b4d576101200190565b8051821015610b4d5760209160051b010190565b61108160206101359361102760a0610f49610e4c565b95610f72610f6d610f6183516001600160401b031690565b6001600160401b031690565b6117e7565b610f7b88610e90565b52610f8587610e90565b50610f92858201516117e7565b610f9b88610e9d565b52610fa587610e9d565b50610fc0610f6d610f6160408401516001600160401b031690565b610fc988610ead565b52610fd387610ead565b506060810151610feb906001600160a01b03166117b5565b610ff488610ebd565b52610ffe87610ebd565b5061100c60808201516117e7565b61101588610ecd565b5261101f87610ecd565b500151611516565b61103085610edd565b5261103a84610edd565b5061104860408201516117e7565b61105185610eed565b5261105b84610eed565b5061106681516117e7565b61106f85610efd565b5261107984610efd565b5001516117e7565b61108a82610f0e565b5261109481610f0e565b50611692565b604051906110a782610467565b60006040838281528260208201520152565b906110cc602092828151948592016100dc565b0190565b909291926110dc61109a565b50604090600080836111496111788251602096878201528681526110ff816104a2565b8351908b88830152878252611113826104a2565b61116c8551611121816104bd565b87815261115c875196879460808d87019a61113c8c60049052565b87015260a08601906100ff565b601f1995868683030160608701526100ff565b90848483030160808501526100ff565b039081018352826104d8565b51906006600160981b015afa9161118d611a5d565b92156111aa575050906111a26105069261122d565b93849161143b565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b805160021015610b4d5760220190565b805160011015610b4d5760210190565b805160031015610b4d5760230190565b805160041015610b4d5760240190565b908151811015610b4d570160200190565b9061123661109a565b9160088151106113e8576001600160f81b0319600360fc1b8161126961125b85610e90565b516001600160f81b03191690565b16036113e857600160f91b808261128261125b866111dc565b16036113e8576112a66112a061129a61125b866111ec565b60f81c90565b60ff1690565b916112b96112a061129a61125b876111fc565b92602184116113e8576112cb84610d3c565b906112e76112a061129a61125b6112e186610d4a565b8a61121c565b93602185116113e85761130d61130061125b858a61121c565b6001600160f81b03191690565b036113e857806113256113208688610d74565b610d58565b036113e857611335865191610d66565b036113e85761134390610d66565b90600490602185146113fa575b602184146113b5575b5090602080928601015194010151916020811061139e575b5060208110611386575b509083526020830152565b61139261139791610cd0565b610cff565b1c3861137b565b6113926113ad91949294610cd0565b1c9138611371565b6113c561125b848896949661121c565b166113e85760206113df6113d98294610d4a565b92610cbc565b93919250611359565b6040516386cd05c560e01b8152600490fd5b93908461140961125b8861120c565b16611420575061141a600591610cbc565b93611350565b6040516386cd05c560e01b8152fd5b6040513d6000823e3d90fd5b916040810190601b825280519260208201906020611477835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa156107975784516001600160a01b0396871696168690036114aa575b505050505050565b6114dc8593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa1561079757516001600160a01b031603611504573880808080806114a2565b604051634532600d60e01b8152600490fd5b90600091805192600193848114908161167a575b501561153557509150565b81519360388510156115a757509261159961013592611593949561157661156660ff61155f6118ba565b9616611930565b60f81b6001600160f81b03191690565b901a61158184610e90565b535b60405194859360208501906110b9565b906110b9565b03601f1981018352826104d8565b9190808380805b611648575b50506115c66115c183610d4a565b6118ec565b936115de6115666115d960ff8616611930565b61191e565b821a6115e986610e90565b535b82811115611609575050506115939293509061159961013592611583565b806116316115666112a06112a061162b611626611643978a610cf2565b611954565b8c61188b565b831a61163d828861121c565b536118ab565b6115eb565b9092611654848961188b565b156116725761166561166b916118ab565b93610d17565b90806115ae565b9250806115b3565b905015610b4d576080602083015160f81c103861152a565b61169b90611963565b80516000603882101561170c57506020610135916116c661156660ff6116bf6118ba565b9316611942565b60001a6116d282610e90565b535b60405193816116ec86935180928680870191016100dc565b8201611700825180938680850191016100dc565b010380845201826104d8565b909260019290915b61171e848661188b565b156117355761166561172f916118ab565b92611714565b9092509290926117476115c182610d4a565b9161175a6115666115d960ff8516611942565b60001a61176684610e90565b5360015b82811115611780575050506020610135916116d4565b806117a36115666112a06112a061179d6116266117b0978a610cf2565b8761188b565b60001a61163d828761121c565b61176a565b61013590604051906bffffffffffffffffffffffff199060601b166020820152601481526117e2816104a2565b611516565b906040516118018161159960209586830160209181520190565b60009283905b808210611861575b5061181c6115c182610cd0565b91845b83518110156118535761184e9061184261125b61183b866118ab565b958561121c565b871a61163d828761121c565b61181f565b505050610135919250611516565b9061187261130061125b838661121c565b6118855761187f906118ab565b90611807565b9061180f565b8115611895570490565b634e487b7160e01b600052601260045260246000fd5b6000198114610ccb5760010190565b604051906118c7826104a2565b6001825260203681840137565b6040516118e0816104bd565b60008152906000368137565b906118f682610515565b61190360405191826104d8565b8281528092611914601f1991610515565b0190602036910137565b60ff60379116019060ff8211610ccb57565b60ff60809116019060ff8211610ccb57565b60ff60c09116019060ff8211610ccb57565b601f8111610ccb576101000a90565b8051156119fc5790600091825b815184101561199e576119926119989161198a8685610f1f565b515190610d74565b936118ab565b92611970565b6119aa919293506118ec565b906020808301936000945b83518610156119f4576119e86119ee916119de6119d28988610f1f565b51868151910183611a05565b61198a8887610f1f565b956118ab565b946119b5565b509350505090565b506101356118d4565b92905b602093848410611a3d5781518152848101809111610ccb57938101809111610ccb5791601f198101908111610ccb5791611a08565b9290919350600019906020036101000a0190811990511690825116179052565b3d15611a88573d90611a6e82610515565b91611a7c60405193846104d8565b82523d6000602084013e565b606090565b15611a9457565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b90601f8111611ae757505050565b600091825260208220906020601f850160051c83019410611b23575b601f0160051c01915b828110611b1857505050565b818155600101611b0c565b9092508290611b03565b91909182516001600160401b03811161048257611b5481611b4e8454610b5e565b84611ad9565b602080601f8311600114611b9757508190611b88939495600092611b8c575b50508160011b916000199060031b1c19161790565b9055565b015190503880611b73565b90601f19831695611bad85600052602060002090565b926000905b888210611bea57505083600195969710611bd1575b505050811b019055565b015160001960f88460031b161c19169055388080611bc7565b80600185968294968601518155019501930190611bb2565b6002546801000000000000000081101561048257806001611c269201600255610b13565b611c7857815191600383101561028e5781546020820151610100600160a81b0360089190911b1660ff949094166001600160a81b03199091161792909217815560409091015161050691600101611b2d565b634e487b7160e01b600052600060045260246000fd5b9080611dad5750600080604051611ca4816104bd565b818152604051611cca8161159960208201946020865260408084015260608301906100ff565b51906001600160981b015afa90611cdf611a5d565b9115611d7257611d6992611d1f611d6e92611d0b611d05611cff87611ef0565b96611f82565b50611de2565b9586935b611d3d611d3686611d1f86610c79565b9060018060a01b0316600052602052604060002090565b5415611a8d565b611d45610508565b90611d508483610b52565b6001600160a01b03861660208301526040820152611c02565b610c79565b5590565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b90611d6992611d1f611d6e92611dda611d0560405187602082015260208152611dd5816104a2565b611f82565b958693611d0f565b6021815103611ede57602181015190805115610b4d576020015160f81c6000600282141580611ed3575b611ec157806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c0808301919091528152611e6681610487565b519060055afa91611e75611a5d565b9215611eaf57611e9a611e94611e8d61013595611ef0565b9384610d74565b60011690565b15611f135790611ea990610cde565b90611f13565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b506003821415611e0c565b604051636446a2c560e11b8152600490fd5b602081519101519060208110611f04575090565b6000199060200360031b1b1690565b6040519160208301918252604083015260408252611f3082610467565b905190206001600160a01b031690565b81601f82011215610293578051611f5681610515565b92611f6460405194856104d8565b818452602082840101116102935761013591602080850191016100dc565b906040908151602090611fa9816115998482019760048952878084015260608301906100ff565b51600094859182916005600160981b015afa90611fc4611a5d565b9115612023578151820191848183850194031261201f5781810151906001600160401b039182811161201b578484611ffe92840101611f40565b9581015191821161201757610135949596500101611f40565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fdfea264697066735822122039f69a38aeb4d953c68f916f3bc6fe1804c5d8a85d4a3d11292c8d4fe347917164736f6c63430008150033";

type AccountFactoryConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AccountFactoryConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class AccountFactory__factory extends ContractFactory {
  constructor(...args: AccountFactoryConstructorParams) {
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
      AccountFactory & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): AccountFactory__factory {
    return super.connect(runner) as AccountFactory__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AccountFactoryInterface {
    return new Interface(_abi) as AccountFactoryInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): AccountFactory {
    return new Contract(address, _abi, runner) as unknown as AccountFactory;
  }
}
