/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Description of the Ezmaxinvoicingsummaryinternal
 * @export
 * @interface MultilingualEzmaxinvoicingsummaryinternalDescription
 */
export interface MultilingualEzmaxinvoicingsummaryinternalDescription {
    /**
     * The Ezmaxinvoicingsummaryinternal description in French
     * @type {string}
     * @memberof MultilingualEzmaxinvoicingsummaryinternalDescription
     */
    'sEzmaxinvoicingsummaryinternalDescription1'?: string;
    /**
     * The Ezmaxinvoicingsummaryinternal description in English
     * @type {string}
     * @memberof MultilingualEzmaxinvoicingsummaryinternalDescription
     */
    'sEzmaxinvoicingsummaryinternalDescription2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualEzmaxinvoicingsummaryinternalDescription Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualEzmaxinvoicingsummaryinternalDescription
 */
export class DataObjectMultilingualEzmaxinvoicingsummaryinternalDescription {
   sEzmaxinvoicingsummaryinternalDescription1?:string = undefined
   sEzmaxinvoicingsummaryinternalDescription2?:string = undefined
}

/**
 * @export 
 * A MultilingualEzmaxinvoicingsummaryinternalDescription Validation Object
 * @class ValidationObjectMultilingualEzmaxinvoicingsummaryinternalDescription
 */
export class ValidationObjectMultilingualEzmaxinvoicingsummaryinternalDescription {
   sEzmaxinvoicingsummaryinternalDescription1 = {
      type: 'string',
      required: false
   }
   sEzmaxinvoicingsummaryinternalDescription2 = {
      type: 'string',
      required: false
   }
} 


