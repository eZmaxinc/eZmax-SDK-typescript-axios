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
import type { SupplyAutocompleteElementResponse } from './supply-autocomplete-element-response';

/**
 * Payload for POST /2/object/supply/getAutocomplete
 * @export
 * @interface SupplyGetAutocompleteV2ResponseMPayload
 */
export interface SupplyGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Supply autocomplete element response.
     * @type {Array<SupplyAutocompleteElementResponse>}
     * @memberof SupplyGetAutocompleteV2ResponseMPayload
     */
    /*'a_objSupply': Array<SupplyAutocompleteElementResponse>;*/
    'a_objSupply': Array<SupplyAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SupplyGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSupplyGetAutocompleteV2ResponseMPayload
 */
export class DataObjectSupplyGetAutocompleteV2ResponseMPayload {
   a_objSupply:Array<SupplyAutocompleteElementResponse> = []
}

/**
 * @export 
 * A SupplyGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectSupplyGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectSupplyGetAutocompleteV2ResponseMPayload {
   a_objSupply = {
      type: 'array',
      required: true
   }
} 


