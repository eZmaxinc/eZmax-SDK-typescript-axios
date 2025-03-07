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
import type { CurrencyAutocompleteElementResponse } from './currency-autocomplete-element-response';

/**
 * Payload for POST /2/object/currency/getAutocomplete
 * @export
 * @interface CurrencyGetAutocompleteV2ResponseMPayload
 */
export interface CurrencyGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Currency autocomplete element response.
     * @type {Array<CurrencyAutocompleteElementResponse>}
     * @memberof CurrencyGetAutocompleteV2ResponseMPayload
     */
    /*'a_objCurrency': Array<CurrencyAutocompleteElementResponse>;*/
    'a_objCurrency': Array<CurrencyAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CurrencyGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCurrencyGetAutocompleteV2ResponseMPayload
 */
export class DataObjectCurrencyGetAutocompleteV2ResponseMPayload {
   a_objCurrency:Array<CurrencyAutocompleteElementResponse> = []
}

/**
 * @export 
 * A CurrencyGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectCurrencyGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectCurrencyGetAutocompleteV2ResponseMPayload {
   a_objCurrency = {
      type: 'array',
      required: true
   }
} 


