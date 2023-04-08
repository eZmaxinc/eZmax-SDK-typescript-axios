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
import { VariableexpenseGetAutocompleteV2ResponseMPayload } from './variableexpense-get-autocomplete-v2-response-mpayload';

/**
 * 
 * @export
 * @interface VariableexpenseGetAutocompleteV2ResponseAllOf
 */
export interface VariableexpenseGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {VariableexpenseGetAutocompleteV2ResponseMPayload}
     * @memberof VariableexpenseGetAutocompleteV2ResponseAllOf
     */
    'mPayload': VariableexpenseGetAutocompleteV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectVariableexpenseGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectVariableexpenseGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A VariableexpenseGetAutocompleteV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseGetAutocompleteV2ResponseAllOf
 */
export class DataObjectVariableexpenseGetAutocompleteV2ResponseAllOf {
   mPayload:VariableexpenseGetAutocompleteV2ResponseMPayload = new DataObjectVariableexpenseGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A VariableexpenseGetAutocompleteV2ResponseAllOf Validation Object
 * @class ValidationObjectVariableexpenseGetAutocompleteV2ResponseAllOf
 */
export class ValidationObjectVariableexpenseGetAutocompleteV2ResponseAllOf {
   mPayload = new ValidationObjectVariableexpenseGetAutocompleteV2ResponseMPayload()
} 


