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
import type { GlaccountAutocompleteElementResponse } from './glaccount-autocomplete-element-response';

/**
 * Payload for POST /2/object/glaccount/getAutocomplete
 * @export
 * @interface GlaccountGetAutocompleteV2ResponseMPayload
 */
export interface GlaccountGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Glaccount autocomplete element response.
     * @type {Array<GlaccountAutocompleteElementResponse>}
     * @memberof GlaccountGetAutocompleteV2ResponseMPayload
     */
    /*'a_objGlaccount': Array<GlaccountAutocompleteElementResponse>;*/
    'a_objGlaccount': Array<GlaccountAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A GlaccountGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectGlaccountGetAutocompleteV2ResponseMPayload
 */
export class DataObjectGlaccountGetAutocompleteV2ResponseMPayload {
   a_objGlaccount:Array<GlaccountAutocompleteElementResponse> = []
}

/**
 * @export 
 * A GlaccountGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectGlaccountGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectGlaccountGetAutocompleteV2ResponseMPayload {
   a_objGlaccount = {
      type: 'array',
      required: true
   }
} 


