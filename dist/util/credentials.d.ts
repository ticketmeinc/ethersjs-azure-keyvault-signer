import { TokenCredential, AccessToken } from '@azure/identity';
/**
 * class implementing StaticTokenCredential for AccessToken compatibility
 */
export declare class StaticTokenCredential implements TokenCredential {
    private accessToken;
    /**
     * @param {AccessToken} accessToken
     */
    constructor(accessToken: AccessToken);
    /**
     * override getToken function from Token Credentials
     * to get the access token object
     */
    getToken(): Promise<AccessToken>;
}
