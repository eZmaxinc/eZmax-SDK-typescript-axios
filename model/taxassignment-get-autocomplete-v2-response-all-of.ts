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
import { TaxassignmentGetAutocompleteV2ResponseMPayload } from './taxassignment-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface TaxassignmentGetAutocompleteV2ResponseAllOf
 */
export interface TaxassignmentGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {TaxassignmentGetAutocompleteV2ResponseMPayload}
     * @memberof TaxassignmentGetAutocompleteV2ResponseAllOf
     */
    'mPayload': TaxassignmentGetAutocompleteV2ResponseMPayload;
}
/**
 * A TaxassignmentGetAutocompleteV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectTaxassignmentGetAutocompleteV2ResponseAllOf
 */
export class DefaultObjectTaxassignmentGetAutocompleteV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<TaxassignmentGetAutocompleteV2ResponseMPayload> = {}
}


