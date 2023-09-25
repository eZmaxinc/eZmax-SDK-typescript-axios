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
import { EzsigntsarequirementAutocompleteElementResponse } from './ezsigntsarequirement-autocomplete-element-response';

/**
 * Payload for POST /2/object/ezsigntsarequirement/getAutocomplete
 * @export
 * @interface EzsigntsarequirementGetAutocompleteV2ResponseMPayload
 */
export interface EzsigntsarequirementGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Ezsigntsarequirement autocomplete element response.
     * @type {Array<EzsigntsarequirementAutocompleteElementResponse>}
     * @memberof EzsigntsarequirementGetAutocompleteV2ResponseMPayload
     */
    'a_objEzsigntsarequirement': Array<EzsigntsarequirementAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntsarequirementGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload
 */
export class DataObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload {
   a_objEzsigntsarequirement:Array<EzsigntsarequirementAutocompleteElementResponse> = []
}

/**
 * @export 
 * A EzsigntsarequirementGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload {
   a_objEzsigntsarequirement = {
      type: 'array',
      required: true
   }
} 


