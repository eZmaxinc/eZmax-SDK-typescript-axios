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
import { PdfalevelAutocompleteElementResponse } from './pdfalevel-autocomplete-element-response';

/**
 * Payload for POST /2/object/pdfalevel/getAutocomplete
 * @export
 * @interface PdfalevelGetAutocompleteV2ResponseMPayload
 */
export interface PdfalevelGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Pdfalevel autocomplete element response.
     * @type {Array<PdfalevelAutocompleteElementResponse>}
     * @memberof PdfalevelGetAutocompleteV2ResponseMPayload
     */
    /*'a_objPdfalevel': Array<PdfalevelAutocompleteElementResponse>;*/
    'a_objPdfalevel': Array<PdfalevelAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PdfalevelGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPdfalevelGetAutocompleteV2ResponseMPayload
 */
export class DataObjectPdfalevelGetAutocompleteV2ResponseMPayload {
   a_objPdfalevel:Array<PdfalevelAutocompleteElementResponse> = []
}

/**
 * @export 
 * A PdfalevelGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectPdfalevelGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectPdfalevelGetAutocompleteV2ResponseMPayload {
   a_objPdfalevel = {
      type: 'array',
      required: true
   }
} 


