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
    'pkiEzmaxinvoicingsummaryglobalID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'fkiEzmaxproductID': number;
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'sEzmaxproductDescriptionX': string;
    /**
     * The start date for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dtEzmaxinvoicingsummaryglobalStart': string;
    /**
     * The end date for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dtEzmaxinvoicingsummaryglobalEnd': string;
    /**
     * The number of days for the Ezmaxinvoicingsummaryglobal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'iEzmaxinvoicingsummaryglobalDays': number;
    /**
     * The The count item calculated
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalCountreal': string;
    /**
     * The The count item billed
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalCountbilled': string;
    /**
     * The Ezmaxinvoicingsummaryglobal subtotal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalSubtotal': string;
    /**
     * The rebate amount for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalRebateamount': string;
    /**
     * The rebate percentage of the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalRebatepercent': string;
    /**
     * The rebate amount total for the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalRebatetotal': string;
    /**
     * The Ezmaxinvoicingsummaryglobal total
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalTotal': string;
    /**
     * The amount of commission for the representative
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalRepresentative'?: string;
    /**
     * The amount of commission for the partner
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalPartner'?: string;
    /**
     * The net amount of the Ezmaxinvoicingsummaryglobal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'dEzmaxinvoicingsummaryglobalNet'?: string;
    /**
     * Whether it is adjustment for the Ezmaxinvoicingsummaryglobal
     * @type {boolean}
     * @memberof EzmaxinvoicingsummaryglobalResponse
     */
    'bEzmaxinvoicingsummaryglobalAdjustment': boolean;
}
/**
 * A EzmaxinvoicingsummaryglobalResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingsummaryglobalResponse
 */
export class DefaultObjectEzmaxinvoicingsummaryglobalResponse extends DefaultObject {
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
}


