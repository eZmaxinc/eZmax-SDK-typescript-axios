/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UserGetAutocompleteV2ResponseMPayload } from './user-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface UserGetAutocompleteV2ResponseAllOf
 */
export interface UserGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {UserGetAutocompleteV2ResponseMPayload}
     * @memberof UserGetAutocompleteV2ResponseAllOf
     */
    'mPayload': UserGetAutocompleteV2ResponseMPayload;
}
/**
 * A UserGetAutocompleteV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectUserGetAutocompleteV2ResponseAllOf
 */
export class DefaultObjectUserGetAutocompleteV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<UserGetAutocompleteV2ResponseMPayload> = {}
}


