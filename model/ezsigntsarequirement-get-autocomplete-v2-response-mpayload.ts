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
import { EzsigntsarequirementAutocompleteElementResponse } from './ezsigntsarequirement-autocomplete-element-response';

import { DefaultObject } from '../base'

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
 * A EzsigntsarequirementGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objEzsigntsarequirement:Array<EzsigntsarequirementAutocompleteElementResponse> = []
}


