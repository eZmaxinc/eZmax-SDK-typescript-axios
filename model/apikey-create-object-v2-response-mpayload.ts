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


import { ApikeyResponseCompound } from './apikey-response-compound';

/**
 * Payload for the /2/object/apikey/createObject API Request
 * @export
 * @interface ApikeyCreateObjectV2ResponseMPayload
 */
export interface ApikeyCreateObjectV2ResponseMPayload {
    /**
     * 
     * @type {Array<ApikeyResponseCompound>}
     * @memberof ApikeyCreateObjectV2ResponseMPayload
     */
    'a_objApikey': Array<ApikeyResponseCompound>;
}

