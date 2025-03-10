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
 * A Ezmaxinvoicingsummaryexternaldetail Object
 * @export
 * @interface EzmaxinvoicingsummaryexternaldetailResponse
 */
export interface EzmaxinvoicingsummaryexternaldetailResponse {
    /**
     * The unique ID of the Ezmaxinvoicingsummaryexternaldetail
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'pkiEzmaxinvoicingsummaryexternaldetailID'?: number;*/
    'pkiEzmaxinvoicingsummaryexternaldetailID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicingsummaryexternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'fkiEzmaxinvoicingsummaryexternalID'?: number;*/
    'fkiEzmaxinvoicingsummaryexternalID'?: number;
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'fkiEzmaxproductID': number;*/
    'fkiEzmaxproductID': number;
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'sEzmaxproductDescriptionX': string;*/
    'sEzmaxproductDescriptionX': string;
    /**
     * The count item invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'dEzmaxinvoicingsummaryexternaldetailCountreal': string;*/
    'dEzmaxinvoicingsummaryexternaldetailCountreal': string;
    /**
     * The subtotal invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'dEzmaxinvoicingsummaryexternaldetailSubtotal': string;*/
    'dEzmaxinvoicingsummaryexternaldetailSubtotal': string;
    /**
     * The rebate for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'dEzmaxinvoicingsummaryexternaldetailRebate': string;*/
    'dEzmaxinvoicingsummaryexternaldetailRebate': string;
    /**
     * The total invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'dEzmaxinvoicingsummaryexternaldetailTotal': string;*/
    'dEzmaxinvoicingsummaryexternaldetailTotal': string;
    /**
     * Whether it\'s an adjustment
     * @type {boolean}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'bEzmaxinvoicingsummaryexternaldetailAdjustment': boolean;*/
    'bEzmaxinvoicingsummaryexternaldetailAdjustment': boolean;
    /**
     * The help message of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    /*'tEzmaxproductHelpX': string;*/
    'tEzmaxproductHelpX': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingsummaryexternaldetailResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryexternaldetailResponse
 */
export class DataObjectEzmaxinvoicingsummaryexternaldetailResponse {
   pkiEzmaxinvoicingsummaryexternaldetailID?:number = undefined
   fkiEzmaxinvoicingsummaryexternalID?:number = undefined
   fkiEzmaxproductID:number = 0
   sEzmaxproductDescriptionX:string = ''
   dEzmaxinvoicingsummaryexternaldetailCountreal:string = ''
   dEzmaxinvoicingsummaryexternaldetailSubtotal:string = ''
   dEzmaxinvoicingsummaryexternaldetailRebate:string = ''
   dEzmaxinvoicingsummaryexternaldetailTotal:string = ''
   bEzmaxinvoicingsummaryexternaldetailAdjustment:boolean = false
   tEzmaxproductHelpX:string = ''
}

/**
 * @export 
 * A EzmaxinvoicingsummaryexternaldetailResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryexternaldetailResponse
 */
export class ValidationObjectEzmaxinvoicingsummaryexternaldetailResponse {
   pkiEzmaxinvoicingsummaryexternaldetailID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxinvoicingsummaryexternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxproductID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzmaxproductDescriptionX = {
      type: 'string',
      required: true
   }
   dEzmaxinvoicingsummaryexternaldetailCountreal = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,6}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryexternaldetailSubtotal = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryexternaldetailRebate = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryexternaldetailTotal = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   bEzmaxinvoicingsummaryexternaldetailAdjustment = {
      type: 'boolean',
      required: true
   }
   tEzmaxproductHelpX = {
      type: 'string',
      required: true
   }
} 


