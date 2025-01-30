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
import type { MultilingualEzmaxinvoicingsummaryinternalDescription } from './multilingual-ezmaxinvoicingsummaryinternal-description';

/**
 * A Ezmaxinvoicingsummaryinternal Object
 * @export
 * @interface EzmaxinvoicingsummaryinternalResponse
 */
export interface EzmaxinvoicingsummaryinternalResponse {
    /**
     * The unique ID of the Ezmaxinvoicingsummaryinternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternalResponse
     */
    /*'pkiEzmaxinvoicingsummaryinternalID'?: number;*/
    'pkiEzmaxinvoicingsummaryinternalID'?: number;
    /**
     * 
     * @type {MultilingualEzmaxinvoicingsummaryinternalDescription}
     * @memberof EzmaxinvoicingsummaryinternalResponse
     */
    /*'objEzmaxinvoicingsummaryinternalDescription': MultilingualEzmaxinvoicingsummaryinternalDescription;*/
    'objEzmaxinvoicingsummaryinternalDescription': MultilingualEzmaxinvoicingsummaryinternalDescription;
    /**
     * The Ezmaxinvoicingsummaryinternal description in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternalResponse
     */
    /*'sEzmaxinvoicingsummaryinternalDescriptionX': string;*/
    'sEzmaxinvoicingsummaryinternalDescriptionX': string;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternalResponse
     */
    /*'fkiEzmaxinvoicingID'?: number;*/
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzmaxinvoicingsummaryinternalResponse
     */
    /*'fkiBillingentityinternalID': number;*/
    'fkiBillingentityinternalID': number;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingsummaryinternalResponse
     */
    /*'sBillingentityinternalDescriptionX': string;*/
    'sBillingentityinternalDescriptionX': string;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzmaxinvoicingsummaryinternalDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzmaxinvoicingsummaryinternalDescription } from './'

/**
 * @export 
 * A EzmaxinvoicingsummaryinternalResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryinternalResponse
 */
export class DataObjectEzmaxinvoicingsummaryinternalResponse {
   pkiEzmaxinvoicingsummaryinternalID?:number = undefined
   objEzmaxinvoicingsummaryinternalDescription:MultilingualEzmaxinvoicingsummaryinternalDescription = new DataObjectMultilingualEzmaxinvoicingsummaryinternalDescription()
   sEzmaxinvoicingsummaryinternalDescriptionX:string = ''
   fkiEzmaxinvoicingID?:number = undefined
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
}

/**
 * @export 
 * A EzmaxinvoicingsummaryinternalResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryinternalResponse
 */
export class ValidationObjectEzmaxinvoicingsummaryinternalResponse {
   pkiEzmaxinvoicingsummaryinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objEzmaxinvoicingsummaryinternalDescription = new ValidationObjectMultilingualEzmaxinvoicingsummaryinternalDescription()
   sEzmaxinvoicingsummaryinternalDescriptionX = {
      type: 'string',
      maxLength: 70,
      required: true
   }
   fkiEzmaxinvoicingID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sBillingentityinternalDescriptionX = {
      type: 'string',
      required: true
   }
} 


