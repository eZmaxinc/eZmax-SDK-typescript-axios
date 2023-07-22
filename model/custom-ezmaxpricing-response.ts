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



/**
 * A Custom Ezmaxpricing Object
 * @export
 * @interface CustomEzmaxpricingResponse
 */
export interface CustomEzmaxpricingResponse {
    /**
     * The unique ID of the Ezmaxpricing
     * @type {number}
     * @memberof CustomEzmaxpricingResponse
     */
    'pkiEzmaxpricingID': number;
    /**
     * The rebate offered when eZsign is taken for all agents
     * @type {string}
     * @memberof CustomEzmaxpricingResponse
     */
    'dEzmaxpricingRebateezsignallagents': string;
    /**
     * The start date of the Ezmaxpricing
     * @type {string}
     * @memberof CustomEzmaxpricingResponse
     */
    'dtEzmaxpricingStart': string;
    /**
     * The end date of the Ezmaxpricing
     * @type {string}
     * @memberof CustomEzmaxpricingResponse
     */
    'dtEzmaxpricingEnd'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzmaxpricingResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzmaxpricingResponse
 */
export class DataObjectCustomEzmaxpricingResponse {
   pkiEzmaxpricingID:number = 0
   dEzmaxpricingRebateezsignallagents:string = ''
   dtEzmaxpricingStart:string = ''
   dtEzmaxpricingEnd?:string = undefined
}

/**
 * @export 
 * A CustomEzmaxpricingResponse Validation Object
 * @class ValidationObjectCustomEzmaxpricingResponse
 */
export class ValidationObjectCustomEzmaxpricingResponse {
   pkiEzmaxpricingID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   dEzmaxpricingRebateezsignallagents = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dtEzmaxpricingStart = {
      type: 'string',
      required: true
   }
   dtEzmaxpricingEnd = {
      type: 'string',
      required: false
   }
} 


