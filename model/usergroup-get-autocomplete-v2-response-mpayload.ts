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
import type { UsergroupAutocompleteElementResponse } from './usergroup-autocomplete-element-response';

/**
 * Payload for POST /2/object/usergroup/getAutocomplete
 * @export
 * @interface UsergroupGetAutocompleteV2ResponseMPayload
 */
export interface UsergroupGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Usergroup autocomplete element response.
     * @type {Array<UsergroupAutocompleteElementResponse>}
     * @memberof UsergroupGetAutocompleteV2ResponseMPayload
     */
    /*'a_objUsergroup': Array<UsergroupAutocompleteElementResponse>;*/
    'a_objUsergroup': Array<UsergroupAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetAutocompleteV2ResponseMPayload
 */
export class DataObjectUsergroupGetAutocompleteV2ResponseMPayload {
   a_objUsergroup:Array<UsergroupAutocompleteElementResponse> = []
}

/**
 * @export 
 * A UsergroupGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectUsergroupGetAutocompleteV2ResponseMPayload {
   a_objUsergroup = {
      type: 'array',
      required: true
   }
} 


