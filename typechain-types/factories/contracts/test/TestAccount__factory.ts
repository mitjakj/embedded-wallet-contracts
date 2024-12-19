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
  "0x60808060405234610085576125168181016001600160401b0381118382101761006f578291610224833903906000f0801561006357600080546001600160a01b0319166001600160a01b0392909216919091179055604051610199908161008b8239f35b6040513d6000823e3d90fd5b634e487b7160e01b600052604160045260246000fd5b600080fdfe608080604052600436101561001357600080fd5b600090813560e01c63b8b1d0cb1461002a57600080fd5b3461015f578160031936011261015f5760018060a01b039060208160c4818686815416631f0f29db60e11b835233600484015281602484015281604484015260806064840152600b60848401526a15195cdd081dd85b1b195d60aa1b60a48401525af19081156101545783916100cc575b506020907fbe2f3d28fdeb5839123d65fd47ec2f5915c715d2b527b9e229123706fdecfc859260405191168152a180f35b905060203d811161014d575b601f8101601f1916820167ffffffffffffffff8111838210176101395760209183916040528101031261013557518181168103610135577fbe2f3d28fdeb5839123d65fd47ec2f5915c715d2b527b9e229123706fdecfc8561009b565b8280fd5b634e487b7160e01b85526041600452602485fd5b503d6100d8565b6040513d85823e3d90fd5b5080fdfea264697066735822122062242d7377a41559be347df8e7a2ddafeefbd57d4563b19eba2d3e0ab91927e064736f6c63430008150033608080604052346100855761213f8181016001600160401b0381118382101761006f5782916103d7833903906000f0801561006357600080546001600160a01b0319166001600160a01b039290921691909117905560405161034c908161008b8239f35b6040513d6000823e3d90fd5b634e487b7160e01b600052604160045260246000fd5b600080fdfe6080604052600436101561001257600080fd5b6000803560e01c633e1e53b61461002857600080fd5b34610101576080366003190112610101576004356001600160a01b03811681036100fd576024359060038210156100f9576064359167ffffffffffffffff8084116100f557366023850112156100f55783600401359081116100f0576040519361009c601f8301601f19166020018661012e565b81855236602483830101116100ec57946020826100ce9695949360246100e899018388013785010152604435916101ea565b6040516001600160a01b0390911681529081906020820190565b0390f35b8580fd5b610104565b8480fd5b8280fd5b5080fd5b80fd5b634e487b7160e01b600052604160045260246000fd5b67ffffffffffffffff81116100f057604052565b90601f8019910116810190811067ffffffffffffffff8211176100f057604052565b6003111561015a57565b634e487b7160e01b600052602160045260246000fd5b600091031261017b57565b600080fd5b9193929060018060a01b03168252602093848301526060604083015280519081606084015260005b8281106101ca57505060809293506000838284010152601f8019910116010190565b8181018601518482016080015285016101a8565b6040513d6000823e3d90fd5b909291926101f781610150565b6102815760005461022990610218908190610224906001600160a01b031682565b6001600160a01b031690565b6102be565b92833b1561017b57600091610252604051948593849363d7e2477f60e01b855260048501610180565b038183865af1801561027c57610266575090565b806102736102799261011a565b80610170565b90565b6101de565b60405162461bcd60e51b8152602060048201526015602482015274416374696f6e206e6f7420737570706f727465642160581b6044820152606490fd5b604051733d602d80600a3d3981f3363d3d373d3d3d363d7360601b815260609190911b6bffffffffffffffffffffffff191660148201526e5af43d82803e903d91602b57fd5bf360881b60288201526037906000f09056fea2646970667358221220ddef185cc1ca1b9dabe90741fe099e67e0e43081a9e0d5bc118a8337cedee28264736f6c634300081500336080806040523461002357600160ff19600054161760005561211690816100298239f35b600080fdfe6080604052600436101561001257600080fd5b60003560e01c8063089b8fae146100e75780631b8b921d146100e2578063260558a0146100dd57806337022e98146100d85780635786ead2146100d357806374e2125a146100ce5780637d1f3b6f146100c957806388196f68146100c4578063a9059cbb146100bf578063b429afeb146100ba578063d7e2477f146100b5578063e341eaa4146100b05763fc9ffe02146100ab57600080fd5b610a61565b61094e565b61088c565b61084d565b6107e0565b610795565b61072d565b6106c0565b610543565b6103b4565b61036b565b6102f9565b610148565b60005b8381106100ff5750506000910152565b81810151838201526020016100ef565b90602091610128815180928185528580860191016100ec565b601f01601f1916010190565b90602061014592818152019061010f565b90565b3461026e5760031960403682011261026e57600435906024356001600160401b039182821161026e5760e090823603011261026e576101b260009333855260016020526101a0600160ff604088205416151514610b0a565b6101ad6002548210610c5f565b610cb5565b506001600160a01b03906101c590610b9a565b51169081845260036020526040842054926101de6104c5565b946101eb83600401610d84565b86526024830135602087015261020360448401610d84565b604087015261021460648401610289565b60608701526084830135608087015260a483013591821161026b5761026761025b87878760c48861024a368a83016004016104fc565b60a0860152013560c0840152610e73565b60405191829182610134565b0390f35b80fd5b600080fd5b600435906001600160a01b038216820361026e57565b35906001600160a01b038216820361026e57565b604060031982011261026e576004356001600160a01b038116810361026e57916024356001600160401b039283821161026e578060238301121561026e57816004013593841161026e576024848301011161026e576024019190565b3461026e576103073661029d565b91600092838093338252600160205261032b600160ff604085205416151514610b0a565b826040519384928337810182815203925af1610345610d00565b9015610363576102679060405191829160208352602083019061010f565b602081519101fd5b3461026e5760008061037c3661029d565b90338452600160205261039a600160ff604087205416151514610b0a565b816040519283928337810184815203915afa610345610d00565b3461026e57604036600319011261026e576103cd610273565b60243580151580910361026e5760009133835260016020526103fa600160ff604086205416151514610b0a565b60018060a01b031682526001602052604082209060ff8019835416911617905580f35b634e487b7160e01b600052604160045260246000fd5b604081019081106001600160401b0382111761044e57604052565b61041d565b606081019081106001600160401b0382111761044e57604052565b60e081019081106001600160401b0382111761044e57604052565b602081019081106001600160401b0382111761044e57604052565b90601f801991011681019081106001600160401b0382111761044e57604052565b604051906104d28261046e565b565b604051906104d282610433565b6001600160401b03811161044e57601f01601f191660200190565b81601f8201121561026e57803590610513826104e1565b9261052160405194856104a4565b8284526020838301011161026e57816000926020809301838601378301015290565b3461026e57604036600319011261026e576001600160401b0360043560243582811161026e576105779036906004016104fc565b60009233845260019260209084825261059a8560ff604089205416151514610b0a565b6105a76002548210610c5f565b835115610683576105b88591610cb5565b500193835192831161044e576105d8836105d28754610b60565b87610d30565b81601f8411600114610618575050819061060893869261060d575b50508160011b916000199060031b1c19161790565b905580f35b0151905038806105f3565b91909383601f19811661063088600052602060002090565b9489905b888383106106695750505010610650575b505050811b01905580f35b015160001960f88460031b161c19169055388080610645565b858701518855909601959485019487935090810190610634565b60405162461bcd60e51b81526004810183905260156024820152745469746c652063616e6e6f7420626520656d70747960581b6044820152606490fd5b3461026e57604036600319011261026e576024356001600160401b03811161026e5761071b6106f560209236906004016104fc565b3360005260018352610713600160ff60406000205416151514610b0a565b600435611c9f565b6040516001600160a01b039091168152f35b3461026e57602036600319011261026e5733600052600160205261075d600160ff60406000205416151514610b0a565b610768600435610cb5565b506001600160a01b039061077b90610b9a565b511660005260036020526020604060002054604051908152f35b3461026e57602036600319011261026e5760206107cc60043533600052600183526101a0600160ff60406000205416151514610b0a565b50546040516001600160a01b039091168152f35b3461026e57604036600319011261026e576107f9610273565b6024359060008080809481943383526001602052610822600160ff604086205416151514610b0a565b82908215610843575b6001600160a01b031690f11561083e5780f35b610cf4565b6108fc915061082b565b3461026e57602036600319011261026e576001600160a01b0361086e610273565b166000526001602052602060ff604060002054166040519015158152f35b3461026e57606036600319011261026e576108a5610273565b6044356001600160401b03811161026e576108c49036906004016104fc565b60ff60005416610914576108ff9160018060a01b031660005260016020526108f76040600020600160ff19825416179055565b602435611c9f565b50610912600160ff196000541617600055565b005b60405162461bcd60e51b8152602060048201526012602482015271105b1c9958591e525b9a5d1a585b1a5e995960721b6044820152606490fd5b3461026e57604036600319011261026e576102676109c1610993600435610973611175565b503360005260016020526101a0600160ff60406000205416151514610b0a565b506001600160a01b03906109a690610b9a565b511680600052600360205260243590604060002054906111ab565b60408051825181526020808401519082015291810151908201529081906060820190565b602080820190808352835180925260409283810182858560051b8401019601946000925b858410610a1a575050505050505090565b909192939495968580610a50600193603f1986820301885286838d51878060a01b0381511684520151918185820152019061010f565b990194019401929594939190610a09565b3461026e5760008060031936011261026b57338152600190602090828252610a938360ff604084205416151514610b0a565b6002805491610aa183610b49565b93610aaf60405195866104a4565b8385528282527f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace8186015b858410610aef576040518061026789826109e5565b84838992610afc85610b9a565b815201920193019290610ada565b15610b1157565b60405162461bcd60e51b815260206004820152601060248201526f27b7363ca13ca1b7b73a3937b63632b960811b6044820152606490fd5b6001600160401b03811161044e5760051b60200190565b90600182811c92168015610b90575b6020831014610b7a57565b634e487b7160e01b600052602260045260246000fd5b91607f1691610b6f565b90604051610ba781610433565b809260018060a01b03815416825260018091019160405192836000825494610bce86610b60565b93848452602096878382169182600014610c3d575050600114610bfe575b5050610bfa925003846104a4565b0152565b86925060005281600020906000915b858310610c25575050610bfa93508201013880610bec565b8054838a018501528894508793909201918101610c0d565b9250935050610bfa94915060ff191682840152151560051b8201013880610bec565b15610c6657565b60405162461bcd60e51b8152602060048201526011602482015270125b9d985b1a59081dd85b1b195d081a59607a1b6044820152606490fd5b634e487b7160e01b600052603260045260246000fd5b600254811015610cef57600260005260011b7f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace0190600090565b610c9f565b6040513d6000823e3d90fd5b3d15610d2b573d90610d11826104e1565b91610d1f60405193846104a4565b82523d6000602084013e565b606090565b90601f8111610d3e57505050565b600091825260208220906020601f850160051c83019410610d7a575b601f0160051c01915b828110610d6f57505050565b818155600101610d63565b9092508290610d5a565b35906001600160401b038216820361026e57565b634e487b7160e01b600052601160045260246000fd5b600019810191908211610dbd57565b610d98565b6020039060208211610dbd57565b6401000003d01990810391908211610dbd57565b91908203918211610dbd57565b600381901b91906001600160fd1b03811603610dbd57565b908160081b918083046101001490151715610dbd57565b9060238201809211610dbd57565b6004019081600411610dbd57565b9060018201809211610dbd57565b9060048201809211610dbd57565b9060028201809211610dbd57565b91908201809211610dbd57565b610ee390929192610e82611175565b5060c0830193610eb0855160405190610e9a82610453565b600082526000602083015260408201528561100e565b604051610eda60208281610ecd81830196878151938492016100ec565b81010380845201826104a4565b519020916111ab565b9060408201805193601a198501948511610dbd57518060011b9080820460021490151715610dbd57610f1b610f209161014596610e66565b610e20565b905261100e565b6040519061014082018281106001600160401b0382111761044e57604052600982528160005b6101208110610f5a575050565b806060602080938501015201610f4d565b805115610cef5760200190565b805160011015610cef5760400190565b805160021015610cef5760600190565b805160031015610cef5760800190565b805160041015610cef5760a00190565b805160051015610cef5760c00190565b805160061015610cef5760e00190565b805160071015610cef576101000190565b805160081015610cef576101200190565b8051821015610cef5760209160051b010190565b61115c60206101459361110260a0611024610f27565b9561104d61104861103c83516001600160401b031690565b6001600160401b031690565b6118b6565b61105688610f6b565b5261106087610f6b565b5061106d858201516118b6565b61107688610f78565b5261108087610f78565b5061109b61104861103c60408401516001600160401b031690565b6110a488610f88565b526110ae87610f88565b5060608101516110c6906001600160a01b0316611884565b6110cf88610f98565b526110d987610f98565b506110e760808201516118b6565b6110f088610fa8565b526110fa87610fa8565b5001516115e5565b61110b85610fb8565b5261111584610fb8565b5061112360408201516118b6565b61112c85610fc8565b5261113684610fc8565b5061114181516118b6565b61114a85610fd8565b5261115484610fd8565b5001516118b6565b61116582610fe9565b5261116f81610fe9565b50611761565b6040519061118282610453565b60006040838281528260208201520152565b906111a7602092828151948592016100ec565b0190565b909291926111b7611175565b50604090600080836112246112538251602096878201528681526111da81610433565b8351908b888301528782526111ee82610433565b61124785516111fc81610489565b878152611237875196879460808d87019a6112178c60049052565b87015260a086019061010f565b601f19958686830301606087015261010f565b908484830301608085015261010f565b039081018352826104a4565b51906006600160981b015afa91611268610d00565b92156112855750509061127d6104d292611308565b93849161150a565b60649250519062461bcd60e51b82526004820152600c60248201526b1cda59db8e8819985a5b195960a21b6044820152fd5b805160021015610cef5760220190565b805160011015610cef5760210190565b805160031015610cef5760230190565b805160041015610cef5760240190565b908151811015610cef570160200190565b90611311611175565b9160088151106114c3576001600160f81b0319600360fc1b8161134461133685610f6b565b516001600160f81b03191690565b16036114c357600160f91b808261135d611336866112b7565b16036114c35761138161137b611375611336866112c7565b60f81c90565b60ff1690565b9161139461137b611375611336876112d7565b92602184116114c3576113a684610e2e565b906113c261137b6113756113366113bc86610e3c565b8a6112f7565b93602185116114c3576113e86113db611336858a6112f7565b6001600160f81b03191690565b036114c357806114006113fb8688610e66565b610e4a565b036114c357611410865191610e58565b036114c35761141e90610e58565b90600490602185146114d5575b60218414611490575b50906020809286010151940101519160208110611479575b5060208110611461575b509083526020830152565b61146d61147291610dc2565b610df1565b1c38611456565b61146d61148891949294610dc2565b1c913861144c565b6114a061133684889694966112f7565b166114c35760206114ba6114b48294610e3c565b92610dae565b93919250611434565b6040516386cd05c560e01b8152600490fd5b9390846114e4611336886112e7565b166114fb57506114f5600591610dae565b9361142b565b6040516386cd05c560e01b8152fd5b916040810190601b825280519260208201906020611546835160405197848960609194939260808201958252601b602083015260408201520152565b866000978892838052039060015afa1561083e5784516001600160a01b039687169616869003611579575b505050505050565b6115ab8593601c602096525192516040519384938460609194939260808201958252601c602083015260408201520152565b838052039060015afa1561083e57516001600160a01b0316036115d357388080808080611571565b604051634532600d60e01b8152600490fd5b906000918051926001938481149081611749575b501561160457509150565b815193603885101561167657509261166861014592611662949561164561163560ff61162e611989565b96166119ff565b60f81b6001600160f81b03191690565b901a61165084610f6b565b535b6040519485936020850190611194565b90611194565b03601f1981018352826104a4565b9190808380805b611717575b505061169561169083610e3c565b6119bb565b936116ad6116356116a860ff86166119ff565b6119ed565b821a6116b886610f6b565b535b828111156116d8575050506116629293509061166861014592611652565b8061170061163561137b61137b6116fa6116f5611712978a610de4565b611a23565b8c61195a565b831a61170c82886112f7565b5361197a565b6116ba565b9092611723848961195a565b156117415761173461173a9161197a565b93610e09565b908061167d565b925080611682565b905015610cef576080602083015160f81c10386115f9565b61176a90611a32565b8051600060388210156117db575060206101459161179561163560ff61178e611989565b9316611a11565b60001a6117a182610f6b565b535b60405193816117bb86935180928680870191016100ec565b82016117cf825180938680850191016100ec565b010380845201826104a4565b909260019290915b6117ed848661195a565b15611804576117346117fe9161197a565b926117e3565b90925092909261181661169082610e3c565b916118296116356116a860ff8516611a11565b60001a61183584610f6b565b5360015b8281111561184f575050506020610145916117a3565b8061187261163561137b61137b61186c6116f561187f978a610de4565b8761195a565b60001a61170c82876112f7565b611839565b61014590604051906bffffffffffffffffffffffff199060601b166020820152601481526118b181610433565b6115e5565b906040516118d08161166860209586830160209181520190565b60009283905b808210611930575b506118eb61169082610dc2565b91845b83518110156119225761191d9061191161133661190a8661197a565b95856112f7565b871a61170c82876112f7565b6118ee565b5050506101459192506115e5565b906119416113db61133683866112f7565b6119545761194e9061197a565b906118d6565b906118de565b8115611964570490565b634e487b7160e01b600052601260045260246000fd5b6000198114610dbd5760010190565b6040519061199682610433565b6001825260203681840137565b6040516119af81610489565b60008152906000368137565b906119c5826104e1565b6119d260405191826104a4565b82815280926119e3601f19916104e1565b0190602036910137565b60ff60379116019060ff8211610dbd57565b60ff60809116019060ff8211610dbd57565b60ff60c09116019060ff8211610dbd57565b601f8111610dbd576101000a90565b805115611acb5790600091825b8151841015611a6d57611a61611a6791611a598685610ffa565b515190610e66565b9361197a565b92611a3f565b611a79919293506119bb565b906020808301936000945b8351861015611ac357611ab7611abd91611aad611aa18988610ffa565b51868151910183611ad4565b611a598887610ffa565b9561197a565b94611a84565b509350505090565b506101456119a3565b92905b602093848410611b0c5781518152848101809111610dbd57938101809111610dbd5791601f198101908111610dbd5791611ad7565b9290919350600019906020036101000a0190811990511690825116179052565b15611b3357565b60405162461bcd60e51b815260206004820152601760248201527f57616c6c657420616c726561647920696d706f727465640000000000000000006044820152606490fd5b600254906801000000000000000082101561044e57611b9e600192838101600255610cb5565b611c8957815181546001600160a01b0319166001600160a01b03919091161781556020918201518051918401939092906001600160401b03831161044e57611bea836105d28754610b60565b81601f8411600114611c1e5750508190611c1a9360009261060d5750508160011b916000199060031b1c19161790565b9055565b91909383601f198116611c3688600052602060002090565b946000905b88838310611c6f5750505010611c56575b505050811b019055565b015160001960f88460031b161c19169055388080611c4c565b858701518855909601959485019487935090810190611c3b565b634e487b7160e01b600052600060045260246000fd5b60646002541015611d755780611d435750611d01611cbb611f18565b9190925b6001600160a01b0384166000908152600360205260409020611ce2905415611b2c565b611cea6104d4565b6001600160a01b0385168152906020820152611b78565b6001600160a01b0382166000908152600360205260409020556001600160a01b038116600090815260016020526040902061014590805460ff19166001179055565b611d01611d6f611d69604051611d6481611668876020830160209181520190565b611ffc565b50611dba565b92611cbf565b60405162461bcd60e51b815260206004820152601b60248201527f4d6178203130302077616c6c65747320706572206163636f756e7400000000006044820152606490fd5b6021815103611eb657602181015190805115610cef576020015160f81c6000600282141580611eab575b611e9957806401000003d019604051602081019160208352602060408301526020606083015280600781808a80098a0908608083015263400000f4600160fe1b0360a083015260c0808301919091528152611e3e8161046e565b519060055afa91611e4d610d00565b9215611e8757611e72611e6c611e6561014595611ec8565b9384610e66565b60011690565b15611eeb5790611e8190610dd0565b90611eeb565b60405163102875ed60e01b8152600490fd5b60405163ab4be04160e01b8152600490fd5b506003821415611de4565b604051636446a2c560e11b8152600490fd5b602081519101519060208110611edc575090565b6000199060200360031b1b1690565b6040519160208301918252604083015260408252611f0882610453565b905190206001600160a01b031690565b600080604051611f2781610489565b818152604051611f4d81611668602082019460208652604080840152606083019061010f565b51906001600160981b015afa611f61610d00565b9015611f7f57611f7c611d69611f7683611ec8565b92611ffc565b91565b60405162461bcd60e51b81526020600482015260136024820152721c985b991bdb509e5d195cce8819985a5b1959606a1b6044820152606490fd5b81601f8201121561026e578051611fd0816104e1565b92611fde60405194856104a4565b8184526020828401011161026e5761014591602080850191016100ec565b9060409081516020906120238161166884820197600489528780840152606083019061010f565b51600094859182916005600160981b015afa9061203e610d00565b911561209d57815182019184818385019403126120995781810151906001600160401b039182811161209557848461207892840101611fba565b9581015191821161209157610145949596500101611fba565b8680fd5b8780fd5b8580fd5b60649084519062461bcd60e51b82526004820152601b60248201527f67656e207369676e696e67206b6579706169723a206661696c656400000000006044820152fdfea2646970667358221220543beaa0e7d91cf666e6987d0c4da0738b6f77d92d03ef799c7ba705f61275f964736f6c63430008150033";

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
