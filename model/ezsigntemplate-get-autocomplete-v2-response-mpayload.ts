/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateAutocompleteElementResponse } from './ezsigntemplate-autocomplete-element-response';

import { DefaultObject } from '../base'

/**
 * Payload for POST /2/object/ezsigntemplate/getAutocomplete
 * @export
 * @interface EzsigntemplateGetAutocompleteV2ResponseMPayload
 */
export interface EzsigntemplateGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Ezsigntemplate autocomplete element response.
     * @type {Array<EzsigntemplateAutocompleteElementResponse>}
     * @memberof EzsigntemplateGetAutocompleteV2ResponseMPayload
     */
    'a_objEzsigntemplate': Array<EzsigntemplateAutocompleteElementResponse>;
}
/**
 * A EzsigntemplateGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectEzsigntemplateGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objEzsigntemplate:Array<EzsigntemplateAutocompleteElementResponse> = []
}


