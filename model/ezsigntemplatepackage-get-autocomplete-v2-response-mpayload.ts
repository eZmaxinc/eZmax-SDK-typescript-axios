/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageAutocompleteElementResponse } from './ezsigntemplatepackage-autocomplete-element-response';

import { DefaultObject } from '../base'

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
    'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageAutocompleteElementResponse>;
}
/**
 * A EzsigntemplatepackageGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageAutocompleteElementResponse> = []
}


