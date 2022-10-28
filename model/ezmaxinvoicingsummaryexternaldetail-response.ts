/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'pkiEzmaxinvoicingsummaryexternaldetailID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicingsummaryexternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'fkiEzmaxinvoicingsummaryexternalID'?: number;
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'fkiEzmaxproductID': number;
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'sEzmaxproductDescriptionX': string;
    /**
     * The count item invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'dEzmaxinvoicingsummaryexternaldetailCountreal': string;
    /**
     * The subtotal invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'dEzmaxinvoicingsummaryexternaldetailSubtotal': string;
    /**
     * The rebate for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'dEzmaxinvoicingsummaryexternaldetailRebate': string;
    /**
     * The total invoiced for the product
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'dEzmaxinvoicingsummaryexternaldetailTotal': string;
    /**
     * Whether it\'s an adjustment
     * @type {boolean}
     * @memberof EzmaxinvoicingsummaryexternaldetailResponse
     */
    'bEzmaxinvoicingsummaryexternaldetailAdjustment': boolean;
}
/**
 * A EzmaxinvoicingsummaryexternaldetailResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingsummaryexternaldetailResponse
 */
export class DefaultObjectEzmaxinvoicingsummaryexternaldetailResponse extends DefaultObject {
   pkiEzmaxinvoicingsummaryexternaldetailID?:number = undefined
   fkiEzmaxinvoicingsummaryexternalID?:number = undefined
   fkiEzmaxproductID:number = 0
   sEzmaxproductDescriptionX:string = ''
   dEzmaxinvoicingsummaryexternaldetailCountreal:string = ''
   dEzmaxinvoicingsummaryexternaldetailSubtotal:string = ''
   dEzmaxinvoicingsummaryexternaldetailRebate:string = ''
   dEzmaxinvoicingsummaryexternaldetailTotal:string = ''
   bEzmaxinvoicingsummaryexternaldetailAdjustment:boolean = false
}


