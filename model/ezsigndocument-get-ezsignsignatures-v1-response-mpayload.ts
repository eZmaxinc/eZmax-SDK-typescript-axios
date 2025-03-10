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
import type { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignsignatures
 * @export
 * @interface EzsigndocumentGetEzsignsignaturesV1ResponseMPayload
 */
export interface EzsigndocumentGetEzsignsignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureResponseCompound>}
     * @memberof EzsigndocumentGetEzsignsignaturesV1ResponseMPayload
     */
    /*'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;*/
    'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentGetEzsignsignaturesV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload
 */
export class DataObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload {
   a_objEzsignsignature:Array<EzsignsignatureResponseCompound> = []
}

/**
 * @export 
 * A EzsigndocumentGetEzsignsignaturesV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload {
   a_objEzsignsignature = {
      type: 'array',
      required: true
   }
} 


