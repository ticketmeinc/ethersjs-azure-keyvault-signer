"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.StaticTokenCredential = void 0;
/**
 * class implementing StaticTokenCredential for AccessToken compatibility
 */
class StaticTokenCredential {
  /**
   * @param {AccessToken} accessToken
   */
  constructor(accessToken) {
    this.accessToken = accessToken;
  }

  /**
   * override getToken function from Token Credentials
   * to get the access token object
   */
  async getToken() {
    return this.accessToken;
  }
}
exports.StaticTokenCredential = StaticTokenCredential;