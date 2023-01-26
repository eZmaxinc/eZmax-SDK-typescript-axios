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
import { PaymenttermAutocompleteElementResponse } from './paymentterm-autocomplete-element-response';

import { DefaultObject } from '../base'

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
    'a_objPaymentterm'?: Array<PaymenttermAutocompleteElementResponse>;
}
/**
 * A PaymenttermGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectPaymenttermGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectPaymenttermGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objPaymentterm?:Array<PaymenttermAutocompleteElementResponse> = undefined
}


