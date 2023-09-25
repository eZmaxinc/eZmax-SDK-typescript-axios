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



/**
 * Payload for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatesignatures
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
 */
export interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
     */
    'a_pkiEzsigntemplatesignatureID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload {
   a_pkiEzsigntemplatesignatureID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload {
   a_pkiEzsigntemplatesignatureID = {
      type: 'array',
      required: true
   }
} 


