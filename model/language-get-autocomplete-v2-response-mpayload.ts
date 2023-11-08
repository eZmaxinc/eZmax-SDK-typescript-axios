/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { LanguageAutocompleteElementResponse } from './language-autocomplete-element-response';

/**
 * Payload for POST /2/object/language/getAutocomplete
 * @export
 * @interface LanguageGetAutocompleteV2ResponseMPayload
 */
export interface LanguageGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Language autocomplete element response.
     * @type {Array<LanguageAutocompleteElementResponse>}
     * @memberof LanguageGetAutocompleteV2ResponseMPayload
     */
    'a_objLanguage': Array<LanguageAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A LanguageGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectLanguageGetAutocompleteV2ResponseMPayload
 */
export class DataObjectLanguageGetAutocompleteV2ResponseMPayload {
   a_objLanguage:Array<LanguageAutocompleteElementResponse> = []
}

/**
 * @export 
 * A LanguageGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectLanguageGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectLanguageGetAutocompleteV2ResponseMPayload {
   a_objLanguage = {
      type: 'array',
      required: true
   }
} 

