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
import { EzsigntsarequirementGetAutocompleteV2ResponseMPayload } from './ezsigntsarequirement-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntsarequirementGetAutocompleteV2ResponseAllOf
 */
export interface EzsigntsarequirementGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {EzsigntsarequirementGetAutocompleteV2ResponseMPayload}
     * @memberof EzsigntsarequirementGetAutocompleteV2ResponseAllOf
     */
    'mPayload': EzsigntsarequirementGetAutocompleteV2ResponseMPayload;
}
/**
 * A EzsigntsarequirementGetAutocompleteV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntsarequirementGetAutocompleteV2ResponseAllOf
 */
export class DefaultObjectEzsigntsarequirementGetAutocompleteV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntsarequirementGetAutocompleteV2ResponseMPayload> = {}
}


