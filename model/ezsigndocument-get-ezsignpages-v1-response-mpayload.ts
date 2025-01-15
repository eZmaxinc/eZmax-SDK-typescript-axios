/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsignpageResponse } from './ezsignpage-response';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignpages
 * @export
 * @interface EzsigndocumentGetEzsignpagesV1ResponseMPayload
 */
export interface EzsigndocumentGetEzsignpagesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignpageResponseCompound>}
     * @memberof EzsigndocumentGetEzsignpagesV1ResponseMPayload
     */
    /*'a_objEzsignpage': Array<EzsignpageResponseCompound>;*/
    'a_objEzsignpage': Array<EzsignpageResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentGetEzsignpagesV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsignpagesV1ResponseMPayload
 */
export class DataObjectEzsigndocumentGetEzsignpagesV1ResponseMPayload {
   a_objEzsignpage:Array<EzsignpageResponseCompound> = []
}

/**
 * @export 
 * A EzsigndocumentGetEzsignpagesV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsignpagesV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetEzsignpagesV1ResponseMPayload {
   a_objEzsignpage = {
      type: 'array',
      required: true
   }
} 


