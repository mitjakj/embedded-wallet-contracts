/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { ethers } from "ethers";
import {
  DeployContractOptions,
  FactoryOptions,
  HardhatEthersHelpers as HardhatEthersHelpersBase,
} from "@nomicfoundation/hardhat-ethers/types";

import * as Contracts from ".";

declare module "hardhat/types/runtime" {
  interface HardhatEthersHelpers extends HardhatEthersHelpersBase {
    getContractFactory(
      name: "EthereumUtils",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.EthereumUtils__factory>;
    getContractFactory(
      name: "AccessControlUpgradeable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccessControlUpgradeable__factory>;
    getContractFactory(
      name: "Initializable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Initializable__factory>;
    getContractFactory(
      name: "UUPSUpgradeable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.UUPSUpgradeable__factory>;
    getContractFactory(
      name: "ContextUpgradeable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ContextUpgradeable__factory>;
    getContractFactory(
      name: "ERC165Upgradeable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC165Upgradeable__factory>;
    getContractFactory(
      name: "IAccessControl",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IAccessControl__factory>;
    getContractFactory(
      name: "Ownable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Ownable__factory>;
    getContractFactory(
      name: "IERC1822Proxiable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC1822Proxiable__factory>;
    getContractFactory(
      name: "IBeacon",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IBeacon__factory>;
    getContractFactory(
      name: "ERC1967Proxy",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC1967Proxy__factory>;
    getContractFactory(
      name: "ERC1967Utils",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC1967Utils__factory>;
    getContractFactory(
      name: "Proxy",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Proxy__factory>;
    getContractFactory(
      name: "Address",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Address__factory>;
    getContractFactory(
      name: "ECDSA",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ECDSA__factory>;
    getContractFactory(
      name: "IERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC165__factory>;
    getContractFactory(
      name: "Math",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Math__factory>;
    getContractFactory(
      name: "Strings",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Strings__factory>;
    getContractFactory(
      name: "Account",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Account__factory>;
    getContractFactory(
      name: "AccountEVM",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccountEVM__factory>;
    getContractFactory(
      name: "AccountFactory",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccountFactory__factory>;
    getContractFactory(
      name: "AccountManager",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccountManager__factory>;
    getContractFactory(
      name: "AccountManagerStorage",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccountManagerStorage__factory>;
    getContractFactory(
      name: "IAccount",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IAccount__factory>;
    getContractFactory(
      name: "IAccountFactory",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IAccountFactory__factory>;
    getContractFactory(
      name: "JWT",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.JWT__factory>;
    getContractFactory(
      name: "SECP256R1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.SECP256R1__factory>;
    getContractFactory(
      name: "SECP256R1Precompile",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.SECP256R1Precompile__factory>;
    getContractFactory(
      name: "SHA1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.SHA1__factory>;
    getContractFactory(
      name: "AccountManagerProxy",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccountManagerProxy__factory>;
    getContractFactory(
      name: "TestAccount",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestAccount__factory>;
    getContractFactory(
      name: "TestAccountTarget",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestAccountTarget__factory>;
    getContractFactory(
      name: "TestBase64",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestBase64__factory>;
    getContractFactory(
      name: "TestHelper",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestHelper__factory>;
    getContractFactory(
      name: "TestJWT",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestJWT__factory>;
    getContractFactory(
      name: "TestMakeJSON",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestMakeJSON__factory>;
    getContractFactory(
      name: "TestOTPSHA1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestOTPSHA1__factory>;
    getContractFactory(
      name: "TestOTPSHA256",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestOTPSHA256__factory>;
    getContractFactory(
      name: "TestP256R1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestP256R1__factory>;
    getContractFactory(
      name: "TestWebAuthN",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TestWebAuthN__factory>;

    getContractAt(
      name: "EthereumUtils",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.EthereumUtils>;
    getContractAt(
      name: "AccessControlUpgradeable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccessControlUpgradeable>;
    getContractAt(
      name: "Initializable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Initializable>;
    getContractAt(
      name: "UUPSUpgradeable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.UUPSUpgradeable>;
    getContractAt(
      name: "ContextUpgradeable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ContextUpgradeable>;
    getContractAt(
      name: "ERC165Upgradeable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ERC165Upgradeable>;
    getContractAt(
      name: "IAccessControl",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IAccessControl>;
    getContractAt(
      name: "Ownable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Ownable>;
    getContractAt(
      name: "IERC1822Proxiable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC1822Proxiable>;
    getContractAt(
      name: "IBeacon",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IBeacon>;
    getContractAt(
      name: "ERC1967Proxy",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ERC1967Proxy>;
    getContractAt(
      name: "ERC1967Utils",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ERC1967Utils>;
    getContractAt(
      name: "Proxy",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Proxy>;
    getContractAt(
      name: "Address",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Address>;
    getContractAt(
      name: "ECDSA",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ECDSA>;
    getContractAt(
      name: "IERC165",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC165>;
    getContractAt(
      name: "Math",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Math>;
    getContractAt(
      name: "Strings",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Strings>;
    getContractAt(
      name: "Account",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Account>;
    getContractAt(
      name: "AccountEVM",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccountEVM>;
    getContractAt(
      name: "AccountFactory",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccountFactory>;
    getContractAt(
      name: "AccountManager",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccountManager>;
    getContractAt(
      name: "AccountManagerStorage",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccountManagerStorage>;
    getContractAt(
      name: "IAccount",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IAccount>;
    getContractAt(
      name: "IAccountFactory",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IAccountFactory>;
    getContractAt(
      name: "JWT",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.JWT>;
    getContractAt(
      name: "SECP256R1",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.SECP256R1>;
    getContractAt(
      name: "SECP256R1Precompile",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.SECP256R1Precompile>;
    getContractAt(
      name: "SHA1",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.SHA1>;
    getContractAt(
      name: "AccountManagerProxy",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccountManagerProxy>;
    getContractAt(
      name: "TestAccount",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestAccount>;
    getContractAt(
      name: "TestAccountTarget",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestAccountTarget>;
    getContractAt(
      name: "TestBase64",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestBase64>;
    getContractAt(
      name: "TestHelper",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestHelper>;
    getContractAt(
      name: "TestJWT",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestJWT>;
    getContractAt(
      name: "TestMakeJSON",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestMakeJSON>;
    getContractAt(
      name: "TestOTPSHA1",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestOTPSHA1>;
    getContractAt(
      name: "TestOTPSHA256",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestOTPSHA256>;
    getContractAt(
      name: "TestP256R1",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestP256R1>;
    getContractAt(
      name: "TestWebAuthN",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TestWebAuthN>;

    deployContract(
      name: "EthereumUtils",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.EthereumUtils>;
    deployContract(
      name: "AccessControlUpgradeable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccessControlUpgradeable>;
    deployContract(
      name: "Initializable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Initializable>;
    deployContract(
      name: "UUPSUpgradeable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.UUPSUpgradeable>;
    deployContract(
      name: "ContextUpgradeable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ContextUpgradeable>;
    deployContract(
      name: "ERC165Upgradeable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC165Upgradeable>;
    deployContract(
      name: "IAccessControl",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IAccessControl>;
    deployContract(
      name: "Ownable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Ownable>;
    deployContract(
      name: "IERC1822Proxiable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1822Proxiable>;
    deployContract(
      name: "IBeacon",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IBeacon>;
    deployContract(
      name: "ERC1967Proxy",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC1967Proxy>;
    deployContract(
      name: "ERC1967Utils",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC1967Utils>;
    deployContract(
      name: "Proxy",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Proxy>;
    deployContract(
      name: "Address",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Address>;
    deployContract(
      name: "ECDSA",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ECDSA>;
    deployContract(
      name: "IERC165",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC165>;
    deployContract(
      name: "Math",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Math>;
    deployContract(
      name: "Strings",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Strings>;
    deployContract(
      name: "Account",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Account>;
    deployContract(
      name: "AccountEVM",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountEVM>;
    deployContract(
      name: "AccountFactory",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountFactory>;
    deployContract(
      name: "AccountManager",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountManager>;
    deployContract(
      name: "AccountManagerStorage",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountManagerStorage>;
    deployContract(
      name: "IAccount",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IAccount>;
    deployContract(
      name: "IAccountFactory",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IAccountFactory>;
    deployContract(
      name: "JWT",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.JWT>;
    deployContract(
      name: "SECP256R1",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SECP256R1>;
    deployContract(
      name: "SECP256R1Precompile",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SECP256R1Precompile>;
    deployContract(
      name: "SHA1",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SHA1>;
    deployContract(
      name: "AccountManagerProxy",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountManagerProxy>;
    deployContract(
      name: "TestAccount",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestAccount>;
    deployContract(
      name: "TestAccountTarget",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestAccountTarget>;
    deployContract(
      name: "TestBase64",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestBase64>;
    deployContract(
      name: "TestHelper",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestHelper>;
    deployContract(
      name: "TestJWT",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestJWT>;
    deployContract(
      name: "TestMakeJSON",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestMakeJSON>;
    deployContract(
      name: "TestOTPSHA1",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestOTPSHA1>;
    deployContract(
      name: "TestOTPSHA256",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestOTPSHA256>;
    deployContract(
      name: "TestP256R1",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestP256R1>;
    deployContract(
      name: "TestWebAuthN",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestWebAuthN>;

    deployContract(
      name: "EthereumUtils",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.EthereumUtils>;
    deployContract(
      name: "AccessControlUpgradeable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccessControlUpgradeable>;
    deployContract(
      name: "Initializable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Initializable>;
    deployContract(
      name: "UUPSUpgradeable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.UUPSUpgradeable>;
    deployContract(
      name: "ContextUpgradeable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ContextUpgradeable>;
    deployContract(
      name: "ERC165Upgradeable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC165Upgradeable>;
    deployContract(
      name: "IAccessControl",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IAccessControl>;
    deployContract(
      name: "Ownable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Ownable>;
    deployContract(
      name: "IERC1822Proxiable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1822Proxiable>;
    deployContract(
      name: "IBeacon",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IBeacon>;
    deployContract(
      name: "ERC1967Proxy",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC1967Proxy>;
    deployContract(
      name: "ERC1967Utils",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC1967Utils>;
    deployContract(
      name: "Proxy",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Proxy>;
    deployContract(
      name: "Address",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Address>;
    deployContract(
      name: "ECDSA",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ECDSA>;
    deployContract(
      name: "IERC165",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC165>;
    deployContract(
      name: "Math",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Math>;
    deployContract(
      name: "Strings",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Strings>;
    deployContract(
      name: "Account",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Account>;
    deployContract(
      name: "AccountEVM",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountEVM>;
    deployContract(
      name: "AccountFactory",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountFactory>;
    deployContract(
      name: "AccountManager",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountManager>;
    deployContract(
      name: "AccountManagerStorage",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountManagerStorage>;
    deployContract(
      name: "IAccount",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IAccount>;
    deployContract(
      name: "IAccountFactory",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IAccountFactory>;
    deployContract(
      name: "JWT",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.JWT>;
    deployContract(
      name: "SECP256R1",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SECP256R1>;
    deployContract(
      name: "SECP256R1Precompile",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SECP256R1Precompile>;
    deployContract(
      name: "SHA1",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SHA1>;
    deployContract(
      name: "AccountManagerProxy",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountManagerProxy>;
    deployContract(
      name: "TestAccount",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestAccount>;
    deployContract(
      name: "TestAccountTarget",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestAccountTarget>;
    deployContract(
      name: "TestBase64",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestBase64>;
    deployContract(
      name: "TestHelper",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestHelper>;
    deployContract(
      name: "TestJWT",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestJWT>;
    deployContract(
      name: "TestMakeJSON",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestMakeJSON>;
    deployContract(
      name: "TestOTPSHA1",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestOTPSHA1>;
    deployContract(
      name: "TestOTPSHA256",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestOTPSHA256>;
    deployContract(
      name: "TestP256R1",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestP256R1>;
    deployContract(
      name: "TestWebAuthN",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TestWebAuthN>;

    // default types
    getContractFactory(
      name: string,
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<ethers.ContractFactory>;
    getContractFactory(
      abi: any[],
      bytecode: ethers.BytesLike,
      signer?: ethers.Signer
    ): Promise<ethers.ContractFactory>;
    getContractAt(
      nameOrAbi: string | any[],
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
  }
}
