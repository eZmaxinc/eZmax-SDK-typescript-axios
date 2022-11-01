/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
 * A CustomEzmaxpricingResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomEzmaxpricingResponse
 */
export class DefaultObjectCustomEzmaxpricingResponse extends DefaultObject {
   pkiEzmaxpricingID:number = 0
   dtEzmaxpricingStart:string = ''
   dtEzmaxpricingEnd?:string = undefined
}


