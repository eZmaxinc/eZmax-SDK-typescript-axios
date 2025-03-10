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
import type { FranchiseofficeAutocompleteElementResponse } from './franchiseoffice-autocomplete-element-response';

/**
 * Payload for POST /2/object/franchiseoffice/getAutocomplete
 * @export
 * @interface FranchiseofficeGetAutocompleteV2ResponseMPayload
 */
export interface FranchiseofficeGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Franchiseoffice autocomplete element response.
     * @type {Array<FranchiseofficeAutocompleteElementResponse>}
     * @memberof FranchiseofficeGetAutocompleteV2ResponseMPayload
     */
    /*'a_objFranchiseoffice': Array<FranchiseofficeAutocompleteElementResponse>;*/
    'a_objFranchiseoffice': Array<FranchiseofficeAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A FranchiseofficeGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchiseofficeGetAutocompleteV2ResponseMPayload
 */
export class DataObjectFranchiseofficeGetAutocompleteV2ResponseMPayload {
   a_objFranchiseoffice:Array<FranchiseofficeAutocompleteElementResponse> = []
}

/**
 * @export 
 * A FranchiseofficeGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectFranchiseofficeGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectFranchiseofficeGetAutocompleteV2ResponseMPayload {
   a_objFranchiseoffice = {
      type: 'array',
      required: true
   }
} 


