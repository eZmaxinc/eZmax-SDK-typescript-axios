/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { FranchisebrokerAutocompleteElementResponse } from './franchisebroker-autocomplete-element-response';

/**
 * Payload for POST /2/object/franchisebroker/getAutocomplete
 * @export
 * @interface FranchisebrokerGetAutocompleteV2ResponseMPayload
 */
export interface FranchisebrokerGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Franchisebroker autocomplete element response.
     * @type {Array<FranchisebrokerAutocompleteElementResponse>}
     * @memberof FranchisebrokerGetAutocompleteV2ResponseMPayload
     */
    /*'a_objFranchisebroker': Array<FranchisebrokerAutocompleteElementResponse>;*/
    'a_objFranchisebroker': Array<FranchisebrokerAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A FranchisebrokerGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchisebrokerGetAutocompleteV2ResponseMPayload
 */
export class DataObjectFranchisebrokerGetAutocompleteV2ResponseMPayload {
   a_objFranchisebroker:Array<FranchisebrokerAutocompleteElementResponse> = []
}

/**
 * @export 
 * A FranchisebrokerGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectFranchisebrokerGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectFranchisebrokerGetAutocompleteV2ResponseMPayload {
   a_objFranchisebroker = {
      type: 'array',
      required: true
   }
} 


