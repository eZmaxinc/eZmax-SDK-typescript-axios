/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { BillingentityexternalAutocompleteElementResponse } from './billingentityexternal-autocomplete-element-response';

/**
 * Payload for POST /2/object/billingentityexternal/getAutocomplete
 * @export
 * @interface BillingentityexternalGetAutocompleteV2ResponseMPayload
 */
export interface BillingentityexternalGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Billingentityexternal autocomplete element response.
     * @type {Array<BillingentityexternalAutocompleteElementResponse>}
     * @memberof BillingentityexternalGetAutocompleteV2ResponseMPayload
     */
    /*'a_objBillingentityexternal': Array<BillingentityexternalAutocompleteElementResponse>;*/
    'a_objBillingentityexternal': Array<BillingentityexternalAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BillingentityexternalGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityexternalGetAutocompleteV2ResponseMPayload
 */
export class DataObjectBillingentityexternalGetAutocompleteV2ResponseMPayload {
   a_objBillingentityexternal:Array<BillingentityexternalAutocompleteElementResponse> = []
}

/**
 * @export 
 * A BillingentityexternalGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectBillingentityexternalGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectBillingentityexternalGetAutocompleteV2ResponseMPayload {
   a_objBillingentityexternal = {
      type: 'array',
      required: true
   }
} 


