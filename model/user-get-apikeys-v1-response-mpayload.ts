/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { ApikeyResponseCompound } from './apikey-response-compound';

/**
 * Response for GET /1/object/user/{pkiUserID}/getApikeys
 * @export
 * @interface UserGetApikeysV1ResponseMPayload
 */
export interface UserGetApikeysV1ResponseMPayload {
    /**
     * 
     * @type {Array<ApikeyResponseCompound>}
     * @memberof UserGetApikeysV1ResponseMPayload
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
 * A UserGetApikeysV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetApikeysV1ResponseMPayload
 */
export class DataObjectUserGetApikeysV1ResponseMPayload {
   a_objApikey:Array<ApikeyResponseCompound> = []
}

/**
 * @export 
 * A UserGetApikeysV1ResponseMPayload Validation Object
 * @class ValidationObjectUserGetApikeysV1ResponseMPayload
 */
export class ValidationObjectUserGetApikeysV1ResponseMPayload {
   a_objApikey = {
      type: 'array',
      minItems: 0,
      required: true
   }
} 


