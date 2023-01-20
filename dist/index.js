"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.AzureKeyVaultSigner = void 0;
var _ethers = require("ethers");
var _azure_utils = require("./util/azure_utils");
function _defineProperty(obj, key, value) { key = _toPropertyKey(key); if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }
function _toPropertyKey(arg) { var key = _toPrimitive(arg, "string"); return typeof key === "symbol" ? key : String(key); }
function _toPrimitive(input, hint) { if (typeof input !== "object" || input === null) return input; var prim = input[Symbol.toPrimitive]; if (prim !== undefined) { var res = prim.call(input, hint || "default"); if (typeof res !== "object") return res; throw new TypeError("@@toPrimitive must return a primitive value."); } return (hint === "string" ? String : Number)(input); }
/**
 * class implementing ethers Signer methods for keys stored in Azure Key Vault
 */
class AzureKeyVaultSigner extends _ethers.ethers.Signer {
  /**
   * @param {AzureKeyVaultCredentials} keyVaultCredentials
   * @param {ethers.providers.Provider} provider
   */
  constructor(keyVaultCredentials, provider) {
    super();
    _defineProperty(this, "keyVaultCredentials", void 0);
    _defineProperty(this, "ethereumAddress", void 0);
    _ethers.ethers.utils.defineReadOnly(this, 'provider', provider);
    _ethers.ethers.utils.defineReadOnly(this, 'keyVaultCredentials', keyVaultCredentials);
  }

  /**
   * Returns Ethereum address for an azure key-vault SECP256-K1 key
   * @return {string}
   */
  async getAddress() {
    if (!this.ethereumAddress) {
      const key = await (0, _azure_utils.getPublicKey)(this.keyVaultCredentials);
      this.ethereumAddress = await (0, _azure_utils.getEthereumAddress)(key);
    }
    return Promise.resolve(this.ethereumAddress);
  }

  /**
   * Signs the digest buffer with an azure key-vault SECP-256K1 key
   * and returns signature
   * @param {string} digestString
   * @return {any}
   */
  async _signDigest(digestString) {
    const digestBuffer = Buffer.from(_ethers.ethers.utils.arrayify(digestString));
    const sig = await (0, _azure_utils.requestAKVSignature)(digestBuffer, this.keyVaultCredentials);
    const ethAddr = await this.getAddress();
    const {
      v
    } = (0, _azure_utils.determineCorrectV)(digestBuffer, sig.r, sig.s, ethAddr);
    return _ethers.ethers.utils.joinSignature({
      v,
      r: `0x${sig.r.toString('hex')}`,
      s: `0x${sig.s.toString('hex')}`
    });
  }

  /**
   * Signs a string or byte array with an azure keyvault SECP-256K1 key
   * @param {string | ethers.utils.Bytes} message
   * @return {string}
   */
  async signMessage(message) {
    return this._signDigest(_ethers.ethers.utils.hashMessage(message));
  }

  /**
   * Signs and serializes a transaction with an azure keyvault SECP-256K1 key
   * @param {ethers.utils.Deferrable<ethers.providers.
   * TransactionRequest>} transaction
   * @return {string}
   */
  async signTransaction(transaction) {
    const unsignedTx = await _ethers.ethers.utils.resolveProperties(transaction);
    // ethers.js v5 doesn't support 'from' field in transaction
    delete unsignedTx['from'];
    const serializedTx = _ethers.ethers.utils.serializeTransaction(unsignedTx);
    const transactionSignature = await this._signDigest(_ethers.ethers.utils.keccak256(serializedTx));
    return _ethers.ethers.utils.serializeTransaction(unsignedTx, transactionSignature);
  }

  /**
   * Facilitates connection to a web3 provider
   * @param {ethers.providers.Provider} provider
   * @return {AzureKeyVaultSigner}
   */
  connect(provider) {
    return new AzureKeyVaultSigner(this.keyVaultCredentials, provider);
  }
}
exports.AzureKeyVaultSigner = AzureKeyVaultSigner;