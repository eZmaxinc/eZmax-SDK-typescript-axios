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
import { ProvinceAutocompleteElementResponse } from './province-autocomplete-element-response';

/**
 * Payload for POST /2/object/province/getAutocomplete
 * @export
 * @interface ProvinceGetAutocompleteV2ResponseMPayload
 */
export interface ProvinceGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Province autocomplete element response.
     * @type {Array<ProvinceAutocompleteElementResponse>}
     * @memberof ProvinceGetAutocompleteV2ResponseMPayload
     */
    /*'a_objProvince': Array<ProvinceAutocompleteElementResponse>;*/
    'a_objProvince': Array<ProvinceAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ProvinceGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectProvinceGetAutocompleteV2ResponseMPayload
 */
export class DataObjectProvinceGetAutocompleteV2ResponseMPayload {
   a_objProvince:Array<ProvinceAutocompleteElementResponse> = []
}

/**
 * @export 
 * A ProvinceGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectProvinceGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectProvinceGetAutocompleteV2ResponseMPayload {
   a_objProvince = {
      type: 'array',
      required: true
   }
} 


