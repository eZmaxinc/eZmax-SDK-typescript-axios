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
import { ModuleAutocompleteElementResponse } from './module-autocomplete-element-response';

/**
 * Payload for POST /2/object/module/getAutocomplete
 * @export
 * @interface ModuleGetAutocompleteV2ResponseMPayload
 */
export interface ModuleGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Module autocomplete element response.
     * @type {Array<ModuleAutocompleteElementResponse>}
     * @memberof ModuleGetAutocompleteV2ResponseMPayload
     */
    /*'a_objModule': Array<ModuleAutocompleteElementResponse>;*/
    'a_objModule': Array<ModuleAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ModuleGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModuleGetAutocompleteV2ResponseMPayload
 */
export class DataObjectModuleGetAutocompleteV2ResponseMPayload {
   a_objModule:Array<ModuleAutocompleteElementResponse> = []
}

/**
 * @export 
 * A ModuleGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectModuleGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectModuleGetAutocompleteV2ResponseMPayload {
   a_objModule = {
      type: 'array',
      required: true
   }
} 


