/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BillingentityinternalGetAutocompleteV2ResponseMPayload } from './billingentityinternal-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface BillingentityinternalGetAutocompleteV2ResponseAllOf
 */
export interface BillingentityinternalGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {BillingentityinternalGetAutocompleteV2ResponseMPayload}
     * @memberof BillingentityinternalGetAutocompleteV2ResponseAllOf
     */
    'mPayload': BillingentityinternalGetAutocompleteV2ResponseMPayload;
}
/**
 * A BillingentityinternalGetAutocompleteV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBillingentityinternalGetAutocompleteV2ResponseAllOf
 */
export class DefaultObjectBillingentityinternalGetAutocompleteV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<BillingentityinternalGetAutocompleteV2ResponseMPayload> = {}
}


