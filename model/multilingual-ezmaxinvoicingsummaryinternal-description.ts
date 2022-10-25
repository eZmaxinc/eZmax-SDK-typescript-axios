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
 * Description of the Ezmaxinvoicingsummaryinternal
 * @export
 * @interface MultilingualEzmaxinvoicingsummaryinternalDescription
 */
export interface MultilingualEzmaxinvoicingsummaryinternalDescription {
    /**
     * The Ezmaxinvoicingsummaryinternal description in french
     * @type {string}
     * @memberof MultilingualEzmaxinvoicingsummaryinternalDescription
     */
    'sEzmaxinvoicingsummaryinternalDescription1'?: string;
    /**
     * The Ezmaxinvoicingsummaryinternal description in english
     * @type {string}
     * @memberof MultilingualEzmaxinvoicingsummaryinternalDescription
     */
    'sEzmaxinvoicingsummaryinternalDescription2'?: string;
}
/**
 * A MultilingualEzmaxinvoicingsummaryinternalDescription Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectMultilingualEzmaxinvoicingsummaryinternalDescription
 */
export class DefaultObjectMultilingualEzmaxinvoicingsummaryinternalDescription extends DefaultObject {
   sEzmaxinvoicingsummaryinternalDescription1?:string = undefined
   sEzmaxinvoicingsummaryinternalDescription2?:string = undefined
}


