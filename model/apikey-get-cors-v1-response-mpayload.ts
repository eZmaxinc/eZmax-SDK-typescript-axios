/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CorsResponseCompound } from './cors-response-compound';

/**
 * Response for GET /1/object/apikey/{pkiApikeyID}/getCors
 * @export
 * @interface ApikeyGetCorsV1ResponseMPayload
 */
export interface ApikeyGetCorsV1ResponseMPayload {
    /**
     * 
     * @type {Array<CorsResponseCompound>}
     * @memberof ApikeyGetCorsV1ResponseMPayload
     */
    'a_objCors': Array<CorsResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ApikeyGetCorsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyGetCorsV1ResponseMPayload
 */
export class DataObjectApikeyGetCorsV1ResponseMPayload {
   a_objCors:Array<CorsResponseCompound> = []
}

/**
 * @export 
 * A ApikeyGetCorsV1ResponseMPayload Validation Object
 * @class ValidationObjectApikeyGetCorsV1ResponseMPayload
 */
export class ValidationObjectApikeyGetCorsV1ResponseMPayload {
   a_objCors = {
      type: 'array',
      required: true
   }
} 


