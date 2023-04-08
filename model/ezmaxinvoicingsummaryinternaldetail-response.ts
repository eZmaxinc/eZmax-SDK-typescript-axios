/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezmaxinvoicingsummaryinternaldetail Object
 * @export
 * @interface EzmaxinvoicingsummaryinternaldetailResponse
 */
export interface EzmaxinvoicingsummaryinternaldetailResponse {
    /**
     * The unique ID of the Ezmaxinvoicingsummaryinternaldetail
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'pkiEzmaxinvoicingsummaryinternaldetailID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicingsummaryinternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'fkiEzmaxinvoicingsummaryinternalID'?: number;
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'fkiEzmaxproductID': number;
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'sEzmaxproductDescriptionX': string;
    /**
     * The unique ID of the Billingentityexternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'fkiBillingentityexternalID': number;
    /**
     * The description of the Billingentityexternal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'sBillingentityexternalDescription': string;
    /**
     * The count item invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'dEzmaxinvoicingsummaryinternaldetailCountreal': string;
    /**
     * The subtotal invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'dEzmaxinvoicingsummaryinternaldetailSubtotal': string;
    /**
     * The rebate for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'dEzmaxinvoicingsummaryinternaldetailRebate': string;
    /**
     * The total invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'dEzmaxinvoicingsummaryinternaldetailTotal': string;
    /**
     * Whether if it\'s an adjustment
     * @type {boolean}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'bEzmaxinvoicingsummaryinternaldetailAdjustment': boolean;
    /**
     * The help message of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternaldetailResponse
     */
    'tEzmaxproductHelpX': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingsummaryinternaldetailResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryinternaldetailResponse
 */
export class DataObjectEzmaxinvoicingsummaryinternaldetailResponse {
   pkiEzmaxinvoicingsummaryinternaldetailID?:number = undefined
   fkiEzmaxinvoicingsummaryinternalID?:number = undefined
   fkiEzmaxproductID:number = 0
   sEzmaxproductDescriptionX:string = ''
   fkiBillingentityexternalID:number = 0
   sBillingentityexternalDescription:string = ''
   dEzmaxinvoicingsummaryinternaldetailCountreal:string = ''
   dEzmaxinvoicingsummaryinternaldetailSubtotal:string = ''
   dEzmaxinvoicingsummaryinternaldetailRebate:string = ''
   dEzmaxinvoicingsummaryinternaldetailTotal:string = ''
   bEzmaxinvoicingsummaryinternaldetailAdjustment:boolean = false
   tEzmaxproductHelpX:string = ''
}

/**
 * @export 
 * A EzmaxinvoicingsummaryinternaldetailResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryinternaldetailResponse
 */
export class ValidationObjectEzmaxinvoicingsummaryinternaldetailResponse {
   pkiEzmaxinvoicingsummaryinternaldetailID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxinvoicingsummaryinternalID = {
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
   fkiBillingentityexternalID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sBillingentityexternalDescription = {
      type: 'string',
      required: true
   }
   dEzmaxinvoicingsummaryinternaldetailCountreal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,6}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryinternaldetailSubtotal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryinternaldetailRebate = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryinternaldetailTotal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   bEzmaxinvoicingsummaryinternaldetailAdjustment = {
      type: 'boolean',
      required: true
   }
   tEzmaxproductHelpX = {
      type: 'string',
      required: true
   }
} 


