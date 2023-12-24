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
import { EzsignsigningreasonAutocompleteElementResponse } from './ezsignsigningreason-autocomplete-element-response';

/**
 * Payload for POST /2/object/ezsignsigningreason/getAutocomplete
 * @export
 * @interface EzsignsigningreasonGetAutocompleteV2ResponseMPayload
 */
export interface EzsignsigningreasonGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Ezsignsigningreason autocomplete element response.
     * @type {Array<EzsignsigningreasonAutocompleteElementResponse>}
     * @memberof EzsignsigningreasonGetAutocompleteV2ResponseMPayload
     */
    'a_objEzsignsigningreason': Array<EzsignsigningreasonAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsigningreasonGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonGetAutocompleteV2ResponseMPayload
 */
export class DataObjectEzsignsigningreasonGetAutocompleteV2ResponseMPayload {
   a_objEzsignsigningreason:Array<EzsignsigningreasonAutocompleteElementResponse> = []
}

/**
 * @export 
 * A EzsignsigningreasonGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsigningreasonGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectEzsignsigningreasonGetAutocompleteV2ResponseMPayload {
   a_objEzsignsigningreason = {
      type: 'array',
      required: true
   }
} 


