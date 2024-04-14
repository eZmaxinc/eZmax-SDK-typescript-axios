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
import { CreditcardclientAutocompleteElementResponse } from './creditcardclient-autocomplete-element-response';

/**
 * Payload for POST /2/object/creditcardclient/getAutocomplete
 * @export
 * @interface CreditcardclientGetAutocompleteV2ResponseMPayload
 */
export interface CreditcardclientGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Creditcardclient autocomplete element response.
     * @type {Array<CreditcardclientAutocompleteElementResponse>}
     * @memberof CreditcardclientGetAutocompleteV2ResponseMPayload
     */
    /*'a_objCreditcardclient': Array<CreditcardclientAutocompleteElementResponse>;*/
    'a_objCreditcardclient': Array<CreditcardclientAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CreditcardclientGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientGetAutocompleteV2ResponseMPayload
 */
export class DataObjectCreditcardclientGetAutocompleteV2ResponseMPayload {
   a_objCreditcardclient:Array<CreditcardclientAutocompleteElementResponse> = []
}

/**
 * @export 
 * A CreditcardclientGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectCreditcardclientGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectCreditcardclientGetAutocompleteV2ResponseMPayload {
   a_objCreditcardclient = {
      type: 'array',
      required: true
   }
} 


