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
import { BrandingAutocompleteElementResponse } from './branding-autocomplete-element-response';

/**
 * Payload for POST /2/object/branding/getAutocomplete
 * @export
 * @interface BrandingGetAutocompleteV2ResponseMPayload
 */
export interface BrandingGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Branding object containing the description, ID and active status about the element.
     * @type {Array<BrandingAutocompleteElementResponse>}
     * @memberof BrandingGetAutocompleteV2ResponseMPayload
     */
    /*'a_objBranding': Array<BrandingAutocompleteElementResponse>;*/
    'a_objBranding': Array<BrandingAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BrandingGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingGetAutocompleteV2ResponseMPayload
 */
export class DataObjectBrandingGetAutocompleteV2ResponseMPayload {
   a_objBranding:Array<BrandingAutocompleteElementResponse> = []
}

/**
 * @export 
 * A BrandingGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectBrandingGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectBrandingGetAutocompleteV2ResponseMPayload {
   a_objBranding = {
      type: 'array',
      required: true
   }
} 


