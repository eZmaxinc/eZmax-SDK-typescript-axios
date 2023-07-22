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



/**
 * A Ezsigntemplateformfieldgroupsigner Object
 * @export
 * @interface EzsigntemplateformfieldgroupsignerResponse
 */
export interface EzsigntemplateformfieldgroupsignerResponse {
    /**
     * The unique ID of the Ezsigntemplateformfieldgroupsigner
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupsignerResponse
     */
    'pkiEzsigntemplateformfieldgroupsignerID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupsignerResponse
     */
    'fkiEzsigntemplatesignerID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldgroupsignerResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupsignerResponse
 */
export class DataObjectEzsigntemplateformfieldgroupsignerResponse {
   pkiEzsigntemplateformfieldgroupsignerID:number = 0
   fkiEzsigntemplatesignerID:number = 0
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupsignerResponse Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupsignerResponse
 */
export class ValidationObjectEzsigntemplateformfieldgroupsignerResponse {
   pkiEzsigntemplateformfieldgroupsignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
} 


