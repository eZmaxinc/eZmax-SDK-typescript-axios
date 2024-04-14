/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { PaymenttermAutocompleteElementResponse } from './paymentterm-autocomplete-element-response';

/**
 * Payload for POST /2/object/paymentterm/getAutocomplete
 * @export
 * @interface PaymenttermGetAutocompleteV2ResponseMPayload
 */
export interface PaymenttermGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Paymentterm autocomplete element response.
     * @type {Array<PaymenttermAutocompleteElementResponse>}
     * @memberof PaymenttermGetAutocompleteV2ResponseMPayload
     */
    /*'a_objPaymentterm': Array<PaymenttermAutocompleteElementResponse>;*/
    'a_objPaymentterm': Array<PaymenttermAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PaymenttermGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermGetAutocompleteV2ResponseMPayload
 */
export class DataObjectPaymenttermGetAutocompleteV2ResponseMPayload {
   a_objPaymentterm:Array<PaymenttermAutocompleteElementResponse> = []
}

/**
 * @export 
 * A PaymenttermGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectPaymenttermGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectPaymenttermGetAutocompleteV2ResponseMPayload {
   a_objPaymentterm = {
      type: 'array',
      required: true
   }
} 


