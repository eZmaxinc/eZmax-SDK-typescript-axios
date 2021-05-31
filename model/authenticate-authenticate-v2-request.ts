/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.44
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for the /2/module/authenticate/authenticate API Request
 * @export
 * @interface AuthenticateAuthenticateV2Request
 */
export interface AuthenticateAuthenticateV2Request {
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof AuthenticateAuthenticateV2Request
     */
    pksCustomerCode: string;
    /**
     * The email address.
     * @type {string}
     * @memberof AuthenticateAuthenticateV2Request
     */
    sEmailAddress?: string;
    /**
     * The Login name of the User.
     * @type {string}
     * @memberof AuthenticateAuthenticateV2Request
     */
    sUserLoginname?: string;
    /**
     * A Password.  Must meet complexity requirements
     * @type {string}
     * @memberof AuthenticateAuthenticateV2Request
     */
    sPassword?: string;
    /**
     * A Password encrypted and encoded in Base64  Must meet complexity requirements
     * @type {string}
     * @memberof AuthenticateAuthenticateV2Request
     */
    sPasswordEncrypted?: string;
}

