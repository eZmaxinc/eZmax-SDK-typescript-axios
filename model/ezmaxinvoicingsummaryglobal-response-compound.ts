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


// May contain unused imports in some cases
// @ts-ignore
import type { EzmaxinvoicingcommissionResponseCompound } from './ezmaxinvoicingcommission-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzmaxinvoicingsummaryglobalResponse } from './ezmaxinvoicingsummaryglobal-response';

/**
 * @type EzmaxinvoicingsummaryglobalResponseCompound
 * A Ezmaxinvoicingsummaryglobal Object
 * @export
 */
/*export type EzmaxinvoicingsummaryglobalResponseCompound = EzmaxinvoicingsummaryglobalResponse;*/
export interface EzmaxinvoicingsummaryglobalResponseCompound {
    /**
     * The unique ID of the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    pkiEzmaxinvoicingsummaryglobalID?:number 
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    fkiEzmaxinvoicingID?:number 
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    fkiEzmaxproductID:number 
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    sEzmaxproductDescriptionX:string 
    /**
     * The start date for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dtEzmaxinvoicingsummaryglobalStart:string 
    /**
     * The end date for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dtEzmaxinvoicingsummaryglobalEnd:string 
    /**
     * The number of days for the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    iEzmaxinvoicingsummaryglobalDays:number 
    /**
     * The count item calculated
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalCountreal:string 
    /**
     * The count item billed
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalCountbilled:string 
    /**
     * The Ezmaxinvoicingsummaryglobal subtotal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalSubtotal:string 
    /**
     * The rebate amount for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalRebateamount:string 
    /**
     * The rebate percentage of the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalRebatepercent:string 
    /**
     * The rebate amount total for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalRebatetotal:string 
    /**
     * The Ezmaxinvoicingsummaryglobal total
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalTotal:string 
    /**
     * The amount of commission for the representative
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalRepresentative?:string 
    /**
     * The amount of commission for the partner
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalPartner?:string 
    /**
     * The net amount of the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    dEzmaxinvoicingsummaryglobalNet?:string 
    /**
     * Whether it is adjustment for the Ezmaxinvoicingsummaryglobal
     * @type {boolean}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    bEzmaxinvoicingsummaryglobalAdjustment:boolean 
    /**
     * The help message of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    tEzmaxproductHelpX:string 
    /**
     * 
     * @type {Array<EzmaxinvoicingcommissionResponseCompound>}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompound
     */
    a_objEzmaxinvoicingcommission?:Array<EzmaxinvoicingcommissionResponseCompound> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingsummaryglobalResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryglobalResponseCompound
 */
export class DataObjectEzmaxinvoicingsummaryglobalResponseCompound {
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
    a_objEzmaxinvoicingcommission?:Array<EzmaxinvoicingcommissionResponseCompound> = undefined
}

/**
 * @export 
 * A EzmaxinvoicingsummaryglobalResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryglobalResponseCompound
 */
export class ValidationObjectEzmaxinvoicingsummaryglobalResponseCompound {
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
      pattern: /^-{0,1}[\d]{1,6}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalCountbilled = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,6}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalSubtotal = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalRebateamount = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalRebatepercent = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,3}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalRebatetotal = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalTotal = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: true
   }
   dEzmaxinvoicingsummaryglobalRepresentative = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: false
   }
   dEzmaxinvoicingsummaryglobalPartner = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      required: false
   }
   dEzmaxinvoicingsummaryglobalNet = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
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
   a_objEzmaxinvoicingcommission = {
      type: 'array',
      required: false
   }
} 


