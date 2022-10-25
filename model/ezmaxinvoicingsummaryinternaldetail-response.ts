/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
}
/**
 * A EzmaxinvoicingsummaryinternaldetailResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingsummaryinternaldetailResponse
 */
export class DefaultObjectEzmaxinvoicingsummaryinternaldetailResponse extends DefaultObject {
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
}

