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



/**
 * A Currency AutocompleteElement Response
 * @export
 * @interface CurrencyAutocompleteElementResponse
 */
export interface CurrencyAutocompleteElementResponse {
    /**
     * The unique ID of the Currency.
     * @type {number}
     * @memberof CurrencyAutocompleteElementResponse
     */
    /*'pkiCurrencyID': number;*/
    'pkiCurrencyID': number;
    /**
     * The description of the Currency in the language of the requester
     * @type {string}
     * @memberof CurrencyAutocompleteElementResponse
     */
    /*'sCurrencyDescriptionX': string;*/
    'sCurrencyDescriptionX': string;
    /**
     * Whether the Currency is active or not
     * @type {boolean}
     * @memberof CurrencyAutocompleteElementResponse
     */
    /*'bCurrencyIsactive': boolean;*/
    'bCurrencyIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CurrencyAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCurrencyAutocompleteElementResponse
 */
export class DataObjectCurrencyAutocompleteElementResponse {
   pkiCurrencyID:number = 0
   sCurrencyDescriptionX:string = ''
   bCurrencyIsactive:boolean = false
}

/**
 * @export 
 * A CurrencyAutocompleteElementResponse Validation Object
 * @class ValidationObjectCurrencyAutocompleteElementResponse
 */
export class ValidationObjectCurrencyAutocompleteElementResponse {
   pkiCurrencyID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sCurrencyDescriptionX = {
      type: 'string',
      pattern: /^.{1,20}$/,
      required: true
   }
   bCurrencyIsactive = {
      type: 'boolean',
      required: true
   }
} 


