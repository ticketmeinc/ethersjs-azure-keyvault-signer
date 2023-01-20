import { AccessToken } from '@azure/identity';
import { ethers } from 'ethers';
/**
 * azure key vault parameters required to
 * instantiate an instance of AzureKeyVaultSigner
 */
export interface AzureKeyVaultCredentials {
    keyName: string;
    vaultUrl: string;
    clientId?: string;
    tenantId?: string;
    clientSecret?: string;
    clientCertificatePath?: string;
    accessToken?: AccessToken;
    keyVersion?: string;
}
/**
 * class implementing ethers Signer methods for keys stored in Azure Key Vault
 */
export declare class AzureKeyVaultSigner extends ethers.Signer {
    keyVaultCredentials: AzureKeyVaultCredentials;
    ethereumAddress: string;
    /**
     * @param {AzureKeyVaultCredentials} keyVaultCredentials
     * @param {ethers.providers.Provider} provider
     */
    constructor(keyVaultCredentials: AzureKeyVaultCredentials, provider?: ethers.providers.Provider);
    /**
     * Returns Ethereum address for an azure key-vault SECP256-K1 key
     * @return {string}
     */
    getAddress(): Promise<string>;
    /**
     * Signs the digest buffer with an azure key-vault SECP-256K1 key
     * and returns signature
     * @param {string} digestString
     * @return {any}
     */
    _signDigest(digestString: string): Promise<string>;
    /**
     * Signs a string or byte array with an azure keyvault SECP-256K1 key
     * @param {string | ethers.utils.Bytes} message
     * @return {string}
     */
    signMessage(message: string | ethers.utils.Bytes): Promise<string>;
    /**
     * Signs and serializes a transaction with an azure keyvault SECP-256K1 key
     * @param {ethers.utils.Deferrable<ethers.providers.
     * TransactionRequest>} transaction
     * @return {string}
     */
    signTransaction(transaction: ethers.utils.Deferrable<ethers.providers.TransactionRequest>): Promise<string>;
    /**
     * Facilitates connection to a web3 provider
     * @param {ethers.providers.Provider} provider
     * @return {AzureKeyVaultSigner}
     */
    connect(provider: ethers.providers.Provider): AzureKeyVaultSigner;
}
