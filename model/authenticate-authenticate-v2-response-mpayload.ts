/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for the /2/module/authenticate/authenticate API Request
 * @export
 * @interface AuthenticateAuthenticateV2ResponseMPayload
 */
export interface AuthenticateAuthenticateV2ResponseMPayload {
    /**
     * The Authorization key
     * @type {string}
     * @memberof AuthenticateAuthenticateV2ResponseMPayload
     */
    'sAuthorization': string;
    /**
     * The secret key
     * @type {string}
     * @memberof AuthenticateAuthenticateV2ResponseMPayload
     */
    'sSecret': string;
}

