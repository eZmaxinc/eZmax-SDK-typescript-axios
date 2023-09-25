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
 * An Ezsigntemplatedocument Object
 * @export
 * @interface EzsigntemplatedocumentRequestPatch
 */
export interface EzsigntemplatedocumentRequestPatch {
    /**
     * The name of the Ezsigntemplatedocument.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequestPatch
     */
    'sEzsigntemplatedocumentName'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentRequestPatch Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentRequestPatch
 */
export class DataObjectEzsigntemplatedocumentRequestPatch {
   sEzsigntemplatedocumentName?:string = undefined
}

/**
 * @export 
 * A EzsigntemplatedocumentRequestPatch Validation Object
 * @class ValidationObjectEzsigntemplatedocumentRequestPatch
 */
export class ValidationObjectEzsigntemplatedocumentRequestPatch {
   sEzsigntemplatedocumentName = {
      type: 'string',
      required: false
   }
} 


