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
import { EzsigntemplateglobalAutocompleteElementResponse } from './ezsigntemplateglobal-autocomplete-element-response';

/**
 * Payload for POST /2/object/ezsigntemplateglobal/getAutocomplete
 * @export
 * @interface EzsigntemplateglobalGetAutocompleteV2ResponseMPayload
 */
export interface EzsigntemplateglobalGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Ezsigntemplateglobal autocomplete element response.
     * @type {Array<EzsigntemplateglobalAutocompleteElementResponse>}
     * @memberof EzsigntemplateglobalGetAutocompleteV2ResponseMPayload
     */
    /*'a_objEzsigntemplateglobal': Array<EzsigntemplateglobalAutocompleteElementResponse>;*/
    'a_objEzsigntemplateglobal': Array<EzsigntemplateglobalAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateglobalGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateglobalGetAutocompleteV2ResponseMPayload
 */
export class DataObjectEzsigntemplateglobalGetAutocompleteV2ResponseMPayload {
   a_objEzsigntemplateglobal:Array<EzsigntemplateglobalAutocompleteElementResponse> = []
}

/**
 * @export 
 * A EzsigntemplateglobalGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplateglobalGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplateglobalGetAutocompleteV2ResponseMPayload {
   a_objEzsigntemplateglobal = {
      type: 'array',
      required: true
   }
} 


