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
import { TimezoneGetAutocompleteV2ResponseMPayload } from './timezone-get-autocomplete-v2-response-mpayload';

/**
 * 
 * @export
 * @interface TimezoneGetAutocompleteV2ResponseAllOf
 */
export interface TimezoneGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {TimezoneGetAutocompleteV2ResponseMPayload}
     * @memberof TimezoneGetAutocompleteV2ResponseAllOf
     */
    'mPayload': TimezoneGetAutocompleteV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectTimezoneGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectTimezoneGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A TimezoneGetAutocompleteV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTimezoneGetAutocompleteV2ResponseAllOf
 */
export class DataObjectTimezoneGetAutocompleteV2ResponseAllOf {
   mPayload:TimezoneGetAutocompleteV2ResponseMPayload = new DataObjectTimezoneGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A TimezoneGetAutocompleteV2ResponseAllOf Validation Object
 * @class ValidationObjectTimezoneGetAutocompleteV2ResponseAllOf
 */
export class ValidationObjectTimezoneGetAutocompleteV2ResponseAllOf {
   mPayload = new ValidationObjectTimezoneGetAutocompleteV2ResponseMPayload()
} 


