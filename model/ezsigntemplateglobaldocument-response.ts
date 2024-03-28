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
 * A Ezsigntemplateglobaldocument Object
 * @export
 * @interface EzsigntemplateglobaldocumentResponse
 */
export interface EzsigntemplateglobaldocumentResponse {
    /**
     * The unique ID of the Ezsigntemplateglobaldocument
     * @type {number}
     * @memberof EzsigntemplateglobaldocumentResponse
     */
    'pkiEzsigntemplateglobaldocumentID': number;
    /**
     * The name of the Ezsigntemplateglobaldocument.
     * @type {string}
     * @memberof EzsigntemplateglobaldocumentResponse
     */
    'sEzsigntemplateglobaldocumentName': string;
    /**
     * The number of pages in the Ezsigntemplateglobaldocument.
     * @type {number}
     * @memberof EzsigntemplateglobaldocumentResponse
     */
    'iEzsigntemplateglobaldocumentPagetotal': number;
    /**
     * The number of total signatures in the Ezsigntemplateglobal.
     * @type {number}
     * @memberof EzsigntemplateglobaldocumentResponse
     */
    'iEzsigntemplateglobaldocumentSignaturetotal': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateglobaldocumentResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateglobaldocumentResponse
 */
export class DataObjectEzsigntemplateglobaldocumentResponse {
   pkiEzsigntemplateglobaldocumentID:number = 0
   sEzsigntemplateglobaldocumentName:string = ''
   iEzsigntemplateglobaldocumentPagetotal:number = 0
   iEzsigntemplateglobaldocumentSignaturetotal:number = 0
}

/**
 * @export 
 * A EzsigntemplateglobaldocumentResponse Validation Object
 * @class ValidationObjectEzsigntemplateglobaldocumentResponse
 */
export class ValidationObjectEzsigntemplateglobaldocumentResponse {
   pkiEzsigntemplateglobaldocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplateglobaldocumentName = {
      type: 'string',
      required: true
   }
   iEzsigntemplateglobaldocumentPagetotal = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsigntemplateglobaldocumentSignaturetotal = {
      type: 'integer',
      required: true
   }
} 


