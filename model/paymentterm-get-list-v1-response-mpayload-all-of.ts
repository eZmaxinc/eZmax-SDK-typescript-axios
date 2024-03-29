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
import { PaymenttermListElement } from './paymentterm-list-element';

/**
 * 
 * @export
 * @interface PaymenttermGetListV1ResponseMPayloadAllOf
 */
export interface PaymenttermGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<PaymenttermListElement>}
     * @memberof PaymenttermGetListV1ResponseMPayloadAllOf
     */
    'a_objPaymentterm': Array<PaymenttermListElement>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PaymenttermGetListV1ResponseMPayloadAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermGetListV1ResponseMPayloadAllOf
 */
export class DataObjectPaymenttermGetListV1ResponseMPayloadAllOf {
   a_objPaymentterm:Array<PaymenttermListElement> = []
}

/**
 * @export 
 * A PaymenttermGetListV1ResponseMPayloadAllOf Validation Object
 * @class ValidationObjectPaymenttermGetListV1ResponseMPayloadAllOf
 */
export class ValidationObjectPaymenttermGetListV1ResponseMPayloadAllOf {
   a_objPaymentterm = {
      type: 'array',
      required: true
   }
} 


