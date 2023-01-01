/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingGetAutocompleteV2ResponseMPayload } from './branding-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface BrandingGetAutocompleteV2ResponseAllOf
 */
export interface BrandingGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {BrandingGetAutocompleteV2ResponseMPayload}
     * @memberof BrandingGetAutocompleteV2ResponseAllOf
     */
    'mPayload': BrandingGetAutocompleteV2ResponseMPayload;
}
/**
 * A BrandingGetAutocompleteV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingGetAutocompleteV2ResponseAllOf
 */
export class DefaultObjectBrandingGetAutocompleteV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<BrandingGetAutocompleteV2ResponseMPayload> = {}
}


