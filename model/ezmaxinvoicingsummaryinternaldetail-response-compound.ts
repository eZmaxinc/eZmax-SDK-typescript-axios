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


// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingsummaryinternaldetailResponse } from './ezmaxinvoicingsummaryinternaldetail-response';

/**
 * @type EzmaxinvoicingsummaryinternaldetailResponseCompound
 * A Ezmaxinvoicingsummaryinternaldetail Object
 * @export
 */
export type EzmaxinvoicingsummaryinternaldetailResponseCompound = EzmaxinvoicingsummaryinternaldetailResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingsummaryinternaldetailResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryinternaldetailResponseCompound
 */
export class DataObjectEzmaxinvoicingsummaryinternaldetailResponseCompound {
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
 * A EzmaxinvoicingsummaryinternaldetailResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryinternaldetailResponseCompound
 */
export class ValidationObjectEzmaxinvoicingsummaryinternaldetailResponseCompound {
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


