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
import { FranchisebrokerAutocompleteElementResponse } from './franchisebroker-autocomplete-element-response';

import { DefaultObject } from '../base'

/**
 * Payload for POST /2/object/franchisebroker/getAutocomplete
 * @export
 * @interface FranchisebrokerGetAutocompleteV2ResponseMPayload
 */
export interface FranchisebrokerGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Franchisebroker autocomplete element response.
     * @type {Array<FranchisebrokerAutocompleteElementResponse>}
     * @memberof FranchisebrokerGetAutocompleteV2ResponseMPayload
     */
    'a_objFranchisebroker'?: Array<FranchisebrokerAutocompleteElementResponse>;
}
/**
 * A FranchisebrokerGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisebrokerGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectFranchisebrokerGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objFranchisebroker?:Array<FranchisebrokerAutocompleteElementResponse> = undefined
}


