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
 * A Ezsigntemplatedocument Object
 * @export
 * @interface EzsigntemplatedocumentResponse
 */
export interface EzsigntemplatedocumentResponse {
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'pkiEzsigntemplatedocumentID': number;*/
    'pkiEzsigntemplatedocumentID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'fkiEzsigntemplateID': number;*/
    'fkiEzsigntemplateID': number;
    /**
     * The name of the Ezsigntemplatedocument.
     * @type {string}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'sEzsigntemplatedocumentName': string;*/
    'sEzsigntemplatedocumentName': string;
    /**
     * The number of pages in the Ezsigntemplatedocument.
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'iEzsigntemplatedocumentPagetotal': number;*/
    'iEzsigntemplatedocumentPagetotal': number;
    /**
     * The number of total signatures in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'iEzsigntemplatedocumentSignaturetotal': number;*/
    'iEzsigntemplatedocumentSignaturetotal': number;
    /**
     * The number of total form fields in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'iEzsigntemplatedocumentFormfieldtotal': number;*/
    'iEzsigntemplatedocumentFormfieldtotal': number;
    /**
     * If the Ezsigntemplatedocument contains signed signatures (From internal or external sources)
     * @type {boolean}
     * @memberof EzsigntemplatedocumentResponse
     */
    /*'bEzsigntemplatedocumentHassignedsignatures': boolean;*/
    'bEzsigntemplatedocumentHassignedsignatures': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentResponse
 */
export class DataObjectEzsigntemplatedocumentResponse {
   pkiEzsigntemplatedocumentID:number = 0
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatedocumentName:string = ''
   iEzsigntemplatedocumentPagetotal:number = 0
   iEzsigntemplatedocumentSignaturetotal:number = 0
   iEzsigntemplatedocumentFormfieldtotal:number = 0
   bEzsigntemplatedocumentHassignedsignatures:boolean = false
}

/**
 * @export 
 * A EzsigntemplatedocumentResponse Validation Object
 * @class ValidationObjectEzsigntemplatedocumentResponse
 */
export class ValidationObjectEzsigntemplatedocumentResponse {
   pkiEzsigntemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplatedocumentName = {
      type: 'string',
      required: true
   }
   iEzsigntemplatedocumentPagetotal = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsigntemplatedocumentSignaturetotal = {
      type: 'integer',
      required: true
   }
   iEzsigntemplatedocumentFormfieldtotal = {
      type: 'integer',
      required: true
   }
   bEzsigntemplatedocumentHassignedsignatures = {
      type: 'boolean',
      required: true
   }
} 


