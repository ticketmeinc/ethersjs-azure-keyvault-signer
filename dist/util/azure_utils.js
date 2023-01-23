"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.determineCorrectV = determineCorrectV;
exports.getCredentials = getCredentials;
exports.getEthereumAddress = getEthereumAddress;
exports.getPublicKey = getPublicKey;
exports.keyVaultConnect = keyVaultConnect;
exports.recoverSignature = recoverSignature;
exports.requestAKVSignature = requestAKVSignature;
exports.sign = sign;
var _ethers = require("ethers");
var _keyvaultKeys = require("@azure/keyvault-keys");
var _identity = require("@azure/identity");
var _bn = require("bn.js");
var _credentials = require("./credentials");
/**
 * function to connect to Key Vault using either
 * client secret or credentials
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 */
async function keyVaultConnect(keyVaultCredentials) {
  try {
    const keyVaultUrl = keyVaultCredentials.vaultUrl;
    const credentials = await getCredentials(keyVaultCredentials);
    return new _keyvaultKeys.KeyClient(keyVaultUrl, credentials);
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * get ClientSecret or ClientCertificate Credential object
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 */
async function getCredentials(keyVaultCredentials) {
  try {
    let credentials;
    if (keyVaultCredentials.useDefaultAzureCredential === true) {
      credentials = new _identity.DefaultAzureCredential();
    } else if (keyVaultCredentials.clientSecret) {
      credentials = new _identity.ClientSecretCredential(keyVaultCredentials.tenantId, keyVaultCredentials.clientId, keyVaultCredentials.clientSecret);
    } else if (keyVaultCredentials.clientCertificatePath) {
      credentials = new _identity.ClientCertificateCredential(keyVaultCredentials.tenantId, keyVaultCredentials.clientId, keyVaultCredentials.clientCertificatePath);
    } else if (keyVaultCredentials.accessToken) {
      credentials = new _credentials.StaticTokenCredential(keyVaultCredentials.accessToken);
    } else {
      throw new Error('Credentials not found');
    }
    return credentials;
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Constructs public key from azure key-vault JWK
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 */
async function getPublicKey(keyVaultCredentials) {
  try {
    const client = await keyVaultConnect(keyVaultCredentials);
    const keyObject = await client.getKey(keyVaultCredentials.keyName);
    const publicKey = Buffer.concat([Uint8Array.from([4]), keyObject.key.x, keyObject.key.y]);
    return publicKey;
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Returns ethereum address for a SECP-256K1 public key
 * @param {Buffer} publicKey
 * @return {string}
 */
async function getEthereumAddress(publicKey) {
  try {
    // remove 0x04 prefix from public to extract Ethereum address
    const publicKeyWithoutPrefix = publicKey.slice(1, publicKey.length);
    // calculate keccak256 hash of public and extract last 20 bytes
    const address = _ethers.ethers.utils.keccak256(publicKeyWithoutPrefix);
    const ethereumAddress = `0x${address.slice(-40)}`;
    return Promise.resolve(ethereumAddress);
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Signs a digest buffer with an azure key-vault SECP-256K1 key
 * using ES256K algorithm
 * @param {Buffer} digest
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 * @return {SignResult}
 */
async function sign(digest, keyVaultCredentials) {
  try {
    const client = await keyVaultConnect(keyVaultCredentials);
    const keyObject = await client.getKey(keyVaultCredentials.keyName);
    const credentials = await getCredentials(keyVaultCredentials);
    const cryptographyClient = new _keyvaultKeys.CryptographyClient(keyObject, credentials);
    const signedDigest = await cryptographyClient.sign('ES256K', digest);
    return signedDigest;
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Recovers public key from an ECDSA signature
 * @param {Buffer} msg
 * @param {BN} r
 * @param {BN} s
 * @param {number} v
 * @return {any}
 */
function recoverPubKeyFromSig(msg, r, s, v) {
  try {
    return _ethers.ethers.utils.recoverAddress(`0x${msg.toString('hex')}`, {
      r: `0x${r.toString('hex')}`,
      s: `0x${s.toString('hex')}`,
      v
    });
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Determines the correct recovery identifier 'v' from an ECSDA signature
 * @param {Buffer} msg
 * @param {BN} r
 * @param {BN} s
 * @param {string} expectedEthAddr
 * @return {any}
 */
function determineCorrectV(msg, r, s, expectedEthAddr) {
  try {
    // This is the wrapper function to find the right v value
    // There are two matching signatures on the elliptic curve
    // we need to find the one that matches to our public key
    // it can be v = 27 or v = 28
    let v = 27;
    let pubKey = recoverPubKeyFromSig(msg, r, s, v);
    if (pubKey.toLowerCase() !== expectedEthAddr.toLowerCase()) {
      // if the pub key for v = 27 does not match
      // it has to be v = 28
      v = 28;
      pubKey = recoverPubKeyFromSig(msg, r, s, v);
    }
    return {
      pubKey,
      v
    };
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Calculates r and s values of an ECDSA signature
 * @param {Buffer} signature
 * @return {any}
 */
function recoverSignature(signature) {
  try {
    const r = new _bn.BN(signature.slice(0, 32));
    const s = new _bn.BN(signature.slice(32, 64));
    const secp256k1N = new _bn.BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16); // max value on the curve
    const secp256k1halfN = secp256k1N.div(new _bn.BN(2)); // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    // if s is less than half of the curve,
    // we're on the "good" side of the curve, we can just return
    return {
      r,
      s: s.gt(secp256k1halfN) ? secp256k1N.sub(s) : s
    };
  } catch (error) {
    throw new Error(error);
  }
}

/**
 * Requests an Azure Key Vault signature for message buffer
 * @param {Buffer} plaintext
 * @param {AzureKeyVaultCredentials} keyVaultCredentials
 * @return {any}
 */
async function requestAKVSignature(plaintext, keyVaultCredentials) {
  try {
    const signResult = await sign(plaintext, keyVaultCredentials);
    if (!signResult.result) {
      throw new Error('Azure Key Vault Signed result empty');
    }
    return recoverSignature(Buffer.from(signResult.result));
  } catch (error) {
    throw new Error(error);
  }
}