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


// May contain unused imports in some cases
// @ts-ignore
import { EmailtypeAutocompleteElementResponse } from './emailtype-autocomplete-element-response';

/**
 * Payload for POST /2/object/emailtype/getAutocomplete
 * @export
 * @interface EmailtypeGetAutocompleteV2ResponseMPayload
 */
export interface EmailtypeGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Emailtype autocomplete element response.
     * @type {Array<EmailtypeAutocompleteElementResponse>}
     * @memberof EmailtypeGetAutocompleteV2ResponseMPayload
     */
    'a_objEmailtype'?: Array<EmailtypeAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EmailtypeGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEmailtypeGetAutocompleteV2ResponseMPayload
 */
export class DataObjectEmailtypeGetAutocompleteV2ResponseMPayload {
   a_objEmailtype?:Array<EmailtypeAutocompleteElementResponse> = undefined
}

/**
 * @export 
 * A EmailtypeGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectEmailtypeGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectEmailtypeGetAutocompleteV2ResponseMPayload {
   a_objEmailtype = {
      type: 'array',
      required: false
   }
} 


