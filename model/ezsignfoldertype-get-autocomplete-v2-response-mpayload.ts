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
import { EzsignfoldertypeAutocompleteElementResponse } from './ezsignfoldertype-autocomplete-element-response';

/**
 * Payload for POST /2/object/ezsignfoldertype/getAutocomplete
 * @export
 * @interface EzsignfoldertypeGetAutocompleteV2ResponseMPayload
 */
export interface EzsignfoldertypeGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Ezsignfoldertype autocomplete element response.
     * @type {Array<EzsignfoldertypeAutocompleteElementResponse>}
     * @memberof EzsignfoldertypeGetAutocompleteV2ResponseMPayload
     */
    /*'a_objEzsignfoldertype': Array<EzsignfoldertypeAutocompleteElementResponse>;*/
    'a_objEzsignfoldertype': Array<EzsignfoldertypeAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldertypeGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeGetAutocompleteV2ResponseMPayload
 */
export class DataObjectEzsignfoldertypeGetAutocompleteV2ResponseMPayload {
   a_objEzsignfoldertype:Array<EzsignfoldertypeAutocompleteElementResponse> = []
}

/**
 * @export 
 * A EzsignfoldertypeGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfoldertypeGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectEzsignfoldertypeGetAutocompleteV2ResponseMPayload {
   a_objEzsignfoldertype = {
      type: 'array',
      required: true
   }
} 


