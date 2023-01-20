/// <reference types="node" />
import { KeyClient, SignResult } from '@azure/keyvault-keys';
import { ClientSecretCredential, ClientCertificateCredential } from '@azure/identity';
import { BN } from 'bn.js';
import { AzureKeyVaultCredentials } from '../index';
import { StaticTokenCredential } from './credentials';
/**
 * function to connect to Key Vault using either
 * client secret or credentials
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 */
export declare function keyVaultConnect(keyVaultCredentials: AzureKeyVaultCredentials): Promise<KeyClient>;
/**
 * get ClientSecret or ClientCertificate Credential object
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 */
export declare function getCredentials(keyVaultCredentials: AzureKeyVaultCredentials): Promise<ClientCertificateCredential | ClientSecretCredential | StaticTokenCredential>;
/**
 * Constructs public key from azure key-vault JWK
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 */
export declare function getPublicKey(keyVaultCredentials: AzureKeyVaultCredentials): Promise<Buffer>;
/**
 * Returns ethereum address for a SECP-256K1 public key
 * @param {Buffer} publicKey
 * @return {string}
 */
export declare function getEthereumAddress(publicKey: Buffer): Promise<string>;
/**
 * Signs a digest buffer with an azure key-vault SECP-256K1 key
 * using ES256K algorithm
 * @param {Buffer} digest
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 * @return {SignResult}
 */
export declare function sign(digest: Buffer, keyVaultCredentials: AzureKeyVaultCredentials): Promise<SignResult>;
/**
 * Determines the correct recovery identifier 'v' from an ECSDA signature
 * @param {Buffer} msg
 * @param {BN} r
 * @param {BN} s
 * @param {string} expectedEthAddr
 * @return {any}
 */
export declare function determineCorrectV(msg: Buffer, r: BN, s: BN, expectedEthAddr: string): {
    pubKey: string;
    v: number;
};
/**
 * Calculates r and s values of an ECDSA signature
 * @param {Buffer} signature
 * @return {any}
 */
export declare function recoverSignature(signature: Buffer): {
    r: any;
    s: any;
};
/**
 * Requests an Azure Key Vault signature for message buffer
 * @param {Buffer} plaintext
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 * @return {any}
 */
export declare function requestAKVSignature(plaintext: Buffer, keyVaultCredentials: AzureKeyVaultCredentials): Promise<{
    r: any;
    s: any;
}>;
