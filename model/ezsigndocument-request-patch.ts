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



/**
 * An Ezsigndocument Object
 * @export
 * @interface EzsigndocumentRequestPatch
 */
export interface EzsigndocumentRequestPatch {
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentRequestPatch
     */
    /*'dtEzsigndocumentDuedate'?: string;*/
    'dtEzsigndocumentDuedate'?: string;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentRequestPatch
     */
    /*'sEzsigndocumentName'?: string;*/
    'sEzsigndocumentName'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentRequestPatch Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentRequestPatch
 */
export class DataObjectEzsigndocumentRequestPatch {
   dtEzsigndocumentDuedate?:string = undefined
   sEzsigndocumentName?:string = undefined
}

/**
 * @export 
 * A EzsigndocumentRequestPatch Validation Object
 * @class ValidationObjectEzsigndocumentRequestPatch
 */
export class ValidationObjectEzsigndocumentRequestPatch {
   dtEzsigndocumentDuedate = {
      type: 'string',
      required: false
   }
   sEzsigndocumentName = {
      type: 'string',
      required: false
   }
} 


