/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyResponseCompound } from './apikey-response-compound';

/**
 * Payload for POST /2/object/apikey
 * @export
 * @interface ApikeyCreateObjectV2ResponseMPayload
 */
export interface ApikeyCreateObjectV2ResponseMPayload {
    /**
     * 
     * @type {Array<ApikeyResponseCompound>}
     * @memberof ApikeyCreateObjectV2ResponseMPayload
     */
    /*'a_objApikey': Array<ApikeyResponseCompound>;*/
    'a_objApikey': Array<ApikeyResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ApikeyCreateObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyCreateObjectV2ResponseMPayload
 */
export class DataObjectApikeyCreateObjectV2ResponseMPayload {
   a_objApikey:Array<ApikeyResponseCompound> = []
}

/**
 * @export 
 * A ApikeyCreateObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectApikeyCreateObjectV2ResponseMPayload
 */
export class ValidationObjectApikeyCreateObjectV2ResponseMPayload {
   a_objApikey = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


