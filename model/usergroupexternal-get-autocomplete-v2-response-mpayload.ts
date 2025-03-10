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
import type { UsergroupexternalAutocompleteElementResponse } from './usergroupexternal-autocomplete-element-response';

/**
 * Payload for POST /2/object/usergroupexternal/getAutocomplete
 * @export
 * @interface UsergroupexternalGetAutocompleteV2ResponseMPayload
 */
export interface UsergroupexternalGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Usergroupexternal autocomplete element response.
     * @type {Array<UsergroupexternalAutocompleteElementResponse>}
     * @memberof UsergroupexternalGetAutocompleteV2ResponseMPayload
     */
    /*'a_objUsergroupexternal': Array<UsergroupexternalAutocompleteElementResponse>;*/
    'a_objUsergroupexternal': Array<UsergroupexternalAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupexternalGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetAutocompleteV2ResponseMPayload
 */
export class DataObjectUsergroupexternalGetAutocompleteV2ResponseMPayload {
   a_objUsergroupexternal:Array<UsergroupexternalAutocompleteElementResponse> = []
}

/**
 * @export 
 * A UsergroupexternalGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupexternalGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectUsergroupexternalGetAutocompleteV2ResponseMPayload {
   a_objUsergroupexternal = {
      type: 'array',
      required: true
   }
} 


