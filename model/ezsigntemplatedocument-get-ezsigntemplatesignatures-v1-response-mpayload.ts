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
import { EzsigntemplatesignatureResponseCompound } from './ezsigntemplatesignature-response-compound';

/**
 * Payload for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocument}/getEzsigntemplatesignatures
 * @export
 * @interface EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload
 */
export interface EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigntemplatesignatureResponseCompound>}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload
     */
    'a_objEzsigntemplatesignature': Array<EzsigntemplatesignatureResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload
 */
export class DataObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload {
   a_objEzsigntemplatesignature:Array<EzsigntemplatesignatureResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload {
   a_objEzsigntemplatesignature = {
      type: 'array',
      required: true
   }
} 


