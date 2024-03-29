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
import { UsergroupGetAutocompleteV2ResponseMPayload } from './usergroup-get-autocomplete-v2-response-mpayload';

/**
 * 
 * @export
 * @interface UsergroupGetAutocompleteV2ResponseAllOf
 */
export interface UsergroupGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {UsergroupGetAutocompleteV2ResponseMPayload}
     * @memberof UsergroupGetAutocompleteV2ResponseAllOf
     */
    'mPayload': UsergroupGetAutocompleteV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupGetAutocompleteV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetAutocompleteV2ResponseAllOf
 */
export class DataObjectUsergroupGetAutocompleteV2ResponseAllOf {
   mPayload:UsergroupGetAutocompleteV2ResponseMPayload = new DataObjectUsergroupGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A UsergroupGetAutocompleteV2ResponseAllOf Validation Object
 * @class ValidationObjectUsergroupGetAutocompleteV2ResponseAllOf
 */
export class ValidationObjectUsergroupGetAutocompleteV2ResponseAllOf {
   mPayload = new ValidationObjectUsergroupGetAutocompleteV2ResponseMPayload()
} 


