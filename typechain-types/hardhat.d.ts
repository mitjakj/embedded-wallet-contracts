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
      name: "IERC1155Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC1155Errors__factory>;
    getContractFactory(
      name: "IERC20Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Errors__factory>;
    getContractFactory(
      name: "IERC721Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Errors__factory>;
    getContractFactory(
      name: "ERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20__factory>;
    getContractFactory(
      name: "IERC20Metadata",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Metadata__factory>;
    getContractFactory(
      name: "IERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20__factory>;
    getContractFactory(
      name: "Account",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Account__factory>;
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
      name: "DummyToken",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.DummyToken__factory>;
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
    getContractFactory(
      name: "TOTPExample",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TOTPExample__factory>;
    getContractFactory(
      name: "WebAuthNExample",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.WebAuthNExample__factory>;
    getContractFactory(
      name: "WebAuthNExampleStorage",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.WebAuthNExampleStorage__factory>;

    getContractAt(
      name: "EthereumUtils",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.EthereumUtils>;
    getContractAt(
      name: "IERC1155Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC1155Errors>;
    getContractAt(
      name: "IERC20Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20Errors>;
    getContractAt(
      name: "IERC721Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC721Errors>;
    getContractAt(
      name: "ERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ERC20>;
    getContractAt(
      name: "IERC20Metadata",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20Metadata>;
    getContractAt(
      name: "IERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20>;
    getContractAt(
      name: "Account",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Account>;
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
      name: "DummyToken",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.DummyToken>;
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
    getContractAt(
      name: "TOTPExample",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TOTPExample>;
    getContractAt(
      name: "WebAuthNExample",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.WebAuthNExample>;
    getContractAt(
      name: "WebAuthNExampleStorage",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.WebAuthNExampleStorage>;

    deployContract(
      name: "EthereumUtils",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.EthereumUtils>;
    deployContract(
      name: "IERC1155Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1155Errors>;
    deployContract(
      name: "IERC20Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Errors>;
    deployContract(
      name: "IERC721Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Errors>;
    deployContract(
      name: "ERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC20>;
    deployContract(
      name: "IERC20Metadata",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Metadata>;
    deployContract(
      name: "IERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20>;
    deployContract(
      name: "Account",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Account>;
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
      name: "DummyToken",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DummyToken>;
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
      name: "TOTPExample",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TOTPExample>;
    deployContract(
      name: "WebAuthNExample",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.WebAuthNExample>;
    deployContract(
      name: "WebAuthNExampleStorage",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.WebAuthNExampleStorage>;

    deployContract(
      name: "EthereumUtils",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.EthereumUtils>;
    deployContract(
      name: "IERC1155Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1155Errors>;
    deployContract(
      name: "IERC20Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Errors>;
    deployContract(
      name: "IERC721Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Errors>;
    deployContract(
      name: "ERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC20>;
    deployContract(
      name: "IERC20Metadata",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Metadata>;
    deployContract(
      name: "IERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20>;
    deployContract(
      name: "Account",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Account>;
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
      name: "DummyToken",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DummyToken>;
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
    deployContract(
      name: "TOTPExample",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TOTPExample>;
    deployContract(
      name: "WebAuthNExample",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.WebAuthNExample>;
    deployContract(
      name: "WebAuthNExampleStorage",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.WebAuthNExampleStorage>;

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
