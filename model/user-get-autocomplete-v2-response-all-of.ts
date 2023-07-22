/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UserGetAutocompleteV2ResponseMPayload } from './user-get-autocomplete-v2-response-mpayload';

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
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A UserGetAutocompleteV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetAutocompleteV2ResponseAllOf
 */
export class DataObjectUserGetAutocompleteV2ResponseAllOf {
   mPayload:UserGetAutocompleteV2ResponseMPayload = new DataObjectUserGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A UserGetAutocompleteV2ResponseAllOf Validation Object
 * @class ValidationObjectUserGetAutocompleteV2ResponseAllOf
 */
export class ValidationObjectUserGetAutocompleteV2ResponseAllOf {
   mPayload = new ValidationObjectUserGetAutocompleteV2ResponseMPayload()
} 


