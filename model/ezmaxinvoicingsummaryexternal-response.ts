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
 * A Ezmaxinvoicingsummaryexternal Object
 * @export
 * @interface EzmaxinvoicingsummaryexternalResponse
 */
export interface EzmaxinvoicingsummaryexternalResponse {
    /**
     * The unique ID of the Ezmaxinvoicingsummaryexternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternalResponse
     */
    /*'pkiEzmaxinvoicingsummaryexternalID'?: number;*/
    'pkiEzmaxinvoicingsummaryexternalID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternalResponse
     */
    /*'fkiEzmaxinvoicingID'?: number;*/
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Billingentityexternal
     * @type {number}
     * @memberof EzmaxinvoicingsummaryexternalResponse
     */
    /*'fkiBillingentityexternalID': number;*/
    'fkiBillingentityexternalID': number;
    /**
     * The description of the Billingentityexternal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternalResponse
     */
    /*'sBillingentityexternalDescription': string;*/
    'sBillingentityexternalDescription': string;
    /**
     * The description of the Ezmaxinvoicingsummaryexternal
     * @type {string}
     * @memberof EzmaxinvoicingsummaryexternalResponse
     */
    /*'sEzmaxinvoicingsummaryexternalDescription': string;*/
    'sEzmaxinvoicingsummaryexternalDescription': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingsummaryexternalResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingsummaryexternalResponse
 */
export class DataObjectEzmaxinvoicingsummaryexternalResponse {
   pkiEzmaxinvoicingsummaryexternalID?:number = undefined
   fkiEzmaxinvoicingID?:number = undefined
   fkiBillingentityexternalID:number = 0
   sBillingentityexternalDescription:string = ''
   sEzmaxinvoicingsummaryexternalDescription:string = ''
}

/**
 * @export 
 * A EzmaxinvoicingsummaryexternalResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingsummaryexternalResponse
 */
export class ValidationObjectEzmaxinvoicingsummaryexternalResponse {
   pkiEzmaxinvoicingsummaryexternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxinvoicingID = {
      type: 'integer',
      minimum: 0,
      required: false
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
   sEzmaxinvoicingsummaryexternalDescription = {
      type: 'string',
      required: true
   }
} 


