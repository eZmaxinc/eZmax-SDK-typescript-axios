/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezmaxinvoicingsummaryglobal Object
 * @export
 * @interface EzmaxinvoicingsummaryglobalResponse
 */
export interface EzmaxinvoicingsummaryglobalResponse {
    /**
     * The unique ID of the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'pkiEzmaxinvoicingsummaryglobalID'?: number;*/
    'pkiEzmaxinvoicingsummaryglobalID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'fkiEzmaxinvoicingID'?: number;*/
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'fkiEzmaxproductID': number;*/
    'fkiEzmaxproductID': number;
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'sEzmaxproductDescriptionX': string;*/
    'sEzmaxproductDescriptionX': string;
    /**
     * The start date for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dtEzmaxinvoicingsummaryglobalStart': string;*/
    'dtEzmaxinvoicingsummaryglobalStart': string;
    /**
     * The end date for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dtEzmaxinvoicingsummaryglobalEnd': string;*/
    'dtEzmaxinvoicingsummaryglobalEnd': string;
    /**
     * The number of days for the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'iEzmaxinvoicingsummaryglobalDays': number;*/
    'iEzmaxinvoicingsummaryglobalDays': number;
    /**
     * The count item calculated
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalCountreal': string;*/
    'dEzmaxinvoicingsummaryglobalCountreal': string;
    /**
     * The count item billed
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalCountbilled': string;*/
    'dEzmaxinvoicingsummaryglobalCountbilled': string;
    /**
     * The Ezmaxinvoicingsummaryglobal subtotal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalSubtotal': string;*/
    'dEzmaxinvoicingsummaryglobalSubtotal': string;
    /**
     * The rebate amount for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalRebateamount': string;*/
    'dEzmaxinvoicingsummaryglobalRebateamount': string;
    /**
     * The rebate percentage of the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalRebatepercent': string;*/
    'dEzmaxinvoicingsummaryglobalRebatepercent': string;
    /**
     * The rebate amount total for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalRebatetotal': string;*/
    'dEzmaxinvoicingsummaryglobalRebatetotal': string;
    /**
     * The Ezmaxinvoicingsummaryglobal total
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalTotal': string;*/
    'dEzmaxinvoicingsummaryglobalTotal': string;
    /**
     * The amount of commission for the representative
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalRepresentative'?: string;*/
    'dEzmaxinvoicingsummaryglobalRepresentative'?: string;
    /**
     * The amount of commission for the partner
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalPartner'?: string;*/
    'dEzmaxinvoicingsummaryglobalPartner'?: string;
    /**
     * The net amount of the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'dEzmaxinvoicingsummaryglobalNet'?: string;*/
    'dEzmaxinvoicingsummaryglobalNet'?: string;
    /**
     * Whether it is adjustment for the Ezmaxinvoicingsummaryglobal
     * @type {boolean}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    /*'bEzmaxinvoicingsummaryglobalAdjustment': boolean;*/
    'bEzmaxinvoicingsummaryglobalAdjustment': boolean;
    /**
     * The help message of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
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
 * A EzmaxinvoicingsummaryglobalResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryglobalResponse
 */
export class DataObjectEzmaxinvoicingsummaryglobalResponse {
   pkiEzmaxinvoicingsummaryglobalID?:number = undefined
   fkiEzmaxinvoicingID?:number = undefined
   fkiEzmaxproductID:number = 0
   sEzmaxproductDescriptionX:string = ''
   dtEzmaxinvoicingsummaryglobalStart:string = ''
   dtEzmaxinvoicingsummaryglobalEnd:string = ''
   iEzmaxinvoicingsummaryglobalDays:number = 0
   dEzmaxinvoicingsummaryglobalCountreal:string = ''
   dEzmaxinvoicingsummaryglobalCountbilled:string = ''
   dEzmaxinvoicingsummaryglobalSubtotal:string = ''
   dEzmaxinvoicingsummaryglobalRebateamount:string = ''
   dEzmaxinvoicingsummaryglobalRebatepercent:string = ''
   dEzmaxinvoicingsummaryglobalRebatetotal:string = ''
   dEzmaxinvoicingsummaryglobalTotal:string = ''
   dEzmaxinvoicingsummaryglobalRepresentative?:string = undefined
   dEzmaxinvoicingsummaryglobalPartner?:string = undefined
   dEzmaxinvoicingsummaryglobalNet?:string = undefined
   bEzmaxinvoicingsummaryglobalAdjustment:boolean = false
   tEzmaxproductHelpX:string = ''
}

/**
 * @export 
 * A EzmaxinvoicingsummaryglobalResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryglobalResponse
 */
export class ValidationObjectEzmaxinvoicingsummaryglobalResponse {
   pkiEzmaxinvoicingsummaryglobalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxinvoicingID = {
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
   dtEzmaxinvoicingsummaryglobalStart = {
      type: 'string',
      required: true
   }
   dtEzmaxinvoicingsummaryglobalEnd = {
      type: 'string',
      required: true
   }
   iEzmaxinvoicingsummaryglobalDays = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   dEzmaxinvoicingsummaryglobalCountreal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,6}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalCountbilled = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,6}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalSubtotal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalRebateamount = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalRebatepercent = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,3}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalRebatetotal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalTotal = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingsummaryglobalRepresentative = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: false
   }
   dEzmaxinvoicingsummaryglobalPartner = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: false
   }
   dEzmaxinvoicingsummaryglobalNet = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: false
   }
   bEzmaxinvoicingsummaryglobalAdjustment = {
      type: 'boolean',
      required: true
   }
   tEzmaxproductHelpX = {
      type: 'string',
      required: true
   }
} 


