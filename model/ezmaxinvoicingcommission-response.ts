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
 * A Ezmaxinvoicingcommission Object
 * @export
 * @interface EzmaxinvoicingcommissionResponse
 */
export interface EzmaxinvoicingcommissionResponse {
    /**
     * The unique ID of the Ezmaxinvoicingcommission
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'pkiEzmaxinvoicingcommissionID'?: number;*/
    'pkiEzmaxinvoicingcommissionID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'fkiEzmaxinvoicingsummaryglobalID'?: number;*/
    'fkiEzmaxinvoicingsummaryglobalID'?: number;
    /**
     * The unique ID of the Ezmaxpartner
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'fkiEzmaxpartnerID'?: number;*/
    'fkiEzmaxpartnerID'?: number;
    /**
     * The unique ID of the Ezmaxrepresentative
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'fkiEzmaxrepresentativeID'?: number;*/
    'fkiEzmaxrepresentativeID'?: number;
    /**
     * The start date for the Ezmaxinvoicingcommission
     * @type {string}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'dtEzmaxinvoicingcommissionStart': string;*/
    'dtEzmaxinvoicingcommissionStart': string;
    /**
     * The end date for the Ezmaxinvoicingcommission
     * @type {string}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'dtEzmaxinvoicingcommissionEnd': string;*/
    'dtEzmaxinvoicingcommissionEnd': string;
    /**
     * This is the number of days during the month on which the Ezmaxinvoigcommission applies
     * @type {number}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'iEzmaxinvoicingcommissionDays': number;*/
    'iEzmaxinvoicingcommissionDays': number;
    /**
     * The amount of Ezmaxinvoicingcommission
     * @type {string}
     * @memberof EzmaxinvoicingcommissionResponse
     */
    /*'dEzmaxinvoicingcommissionAmount': string;*/
    'dEzmaxinvoicingcommissionAmount': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingcommissionResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingcommissionResponse
 */
export class DataObjectEzmaxinvoicingcommissionResponse {
   pkiEzmaxinvoicingcommissionID?:number = undefined
   fkiEzmaxinvoicingsummaryglobalID?:number = undefined
   fkiEzmaxpartnerID?:number = undefined
   fkiEzmaxrepresentativeID?:number = undefined
   dtEzmaxinvoicingcommissionStart:string = ''
   dtEzmaxinvoicingcommissionEnd:string = ''
   iEzmaxinvoicingcommissionDays:number = 0
   dEzmaxinvoicingcommissionAmount:string = ''
}

/**
 * @export 
 * A EzmaxinvoicingcommissionResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingcommissionResponse
 */
export class ValidationObjectEzmaxinvoicingcommissionResponse {
   pkiEzmaxinvoicingcommissionID = {
      type: 'integer',
      required: false
   }
   fkiEzmaxinvoicingsummaryglobalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxpartnerID = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   fkiEzmaxrepresentativeID = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   dtEzmaxinvoicingcommissionStart = {
      type: 'string',
      required: true
   }
   dtEzmaxinvoicingcommissionEnd = {
      type: 'string',
      required: true
   }
   iEzmaxinvoicingcommissionDays = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dEzmaxinvoicingcommissionAmount = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
} 


