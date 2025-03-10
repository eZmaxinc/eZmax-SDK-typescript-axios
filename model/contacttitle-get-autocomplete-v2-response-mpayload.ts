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
import type { ContacttitleAutocompleteElementResponse } from './contacttitle-autocomplete-element-response';

/**
 * Payload for POST /2/object/contacttitle/getAutocomplete
 * @export
 * @interface ContacttitleGetAutocompleteV2ResponseMPayload
 */
export interface ContacttitleGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Contacttitle autocomplete element response.
     * @type {Array<ContacttitleAutocompleteElementResponse>}
     * @memberof ContacttitleGetAutocompleteV2ResponseMPayload
     */
    /*'a_objContacttitle': Array<ContacttitleAutocompleteElementResponse>;*/
    'a_objContacttitle': Array<ContacttitleAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ContacttitleGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContacttitleGetAutocompleteV2ResponseMPayload
 */
export class DataObjectContacttitleGetAutocompleteV2ResponseMPayload {
   a_objContacttitle:Array<ContacttitleAutocompleteElementResponse> = []
}

/**
 * @export 
 * A ContacttitleGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectContacttitleGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectContacttitleGetAutocompleteV2ResponseMPayload {
   a_objContacttitle = {
      type: 'array',
      required: true
   }
} 


