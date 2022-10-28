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
import { TaxassignmentAutocompleteElementResponse } from './taxassignment-autocomplete-element-response';

import { DefaultObject } from '../base'

/**
 * Payload for POST /2/object/taxassignment/getAutocomplete
 * @export
 * @interface TaxassignmentGetAutocompleteV2ResponseMPayload
 */
export interface TaxassignmentGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Taxassignment autocomplete element response.
     * @type {Array<TaxassignmentAutocompleteElementResponse>}
     * @memberof TaxassignmentGetAutocompleteV2ResponseMPayload
     */
    'a_objTaxassignment': Array<TaxassignmentAutocompleteElementResponse>;
}
/**
 * A TaxassignmentGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectTaxassignmentGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectTaxassignmentGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objTaxassignment:Array<TaxassignmentAutocompleteElementResponse> = []
}


