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
import type { GlaccountcontainerAutocompleteElementResponse } from './glaccountcontainer-autocomplete-element-response';

/**
 * Payload for POST /2/object/glaccountcontainer/getAutocomplete
 * @export
 * @interface GlaccountcontainerGetAutocompleteV2ResponseMPayload
 */
export interface GlaccountcontainerGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Glaccountcontainer autocomplete element response.
     * @type {Array<GlaccountcontainerAutocompleteElementResponse>}
     * @memberof GlaccountcontainerGetAutocompleteV2ResponseMPayload
     */
    /*'a_objGlaccountcontainer': Array<GlaccountcontainerAutocompleteElementResponse>;*/
    'a_objGlaccountcontainer': Array<GlaccountcontainerAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A GlaccountcontainerGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectGlaccountcontainerGetAutocompleteV2ResponseMPayload
 */
export class DataObjectGlaccountcontainerGetAutocompleteV2ResponseMPayload {
   a_objGlaccountcontainer:Array<GlaccountcontainerAutocompleteElementResponse> = []
}

/**
 * @export 
 * A GlaccountcontainerGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectGlaccountcontainerGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectGlaccountcontainerGetAutocompleteV2ResponseMPayload {
   a_objGlaccountcontainer = {
      type: 'array',
      required: true
   }
} 


