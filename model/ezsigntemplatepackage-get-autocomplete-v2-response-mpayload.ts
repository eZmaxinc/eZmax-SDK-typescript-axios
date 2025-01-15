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
import type { EzsigntemplatepackageAutocompleteElementResponse } from './ezsigntemplatepackage-autocomplete-element-response';

/**
 * Payload for POST /2/object/ezsigntemplatepackage/getAutocomplete
 * @export
 * @interface EzsigntemplatepackageGetAutocompleteV2ResponseMPayload
 */
export interface EzsigntemplatepackageGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Ezsigntemplatepackage autocomplete element response.
     * @type {Array<EzsigntemplatepackageAutocompleteElementResponse>}
     * @memberof EzsigntemplatepackageGetAutocompleteV2ResponseMPayload
     */
    /*'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageAutocompleteElementResponse>;*/
    'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload
 */
export class DataObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload {
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageAutocompleteElementResponse> = []
}

/**
 * @export 
 * A EzsigntemplatepackageGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload {
   a_objEzsigntemplatepackage = {
      type: 'array',
      required: true
   }
} 


