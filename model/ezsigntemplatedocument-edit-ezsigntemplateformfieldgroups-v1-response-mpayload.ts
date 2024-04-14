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
 * Payload for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplateformfieldgroups
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload
 */
export interface EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload
     */
    /*'a_pkiEzsigntemplateformfieldgroupID': Array<number>;*/
    'a_pkiEzsigntemplateformfieldgroupID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload {
   a_pkiEzsigntemplateformfieldgroupID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload {
   a_pkiEzsigntemplateformfieldgroupID = {
      type: 'array',
      required: true
   }
} 


