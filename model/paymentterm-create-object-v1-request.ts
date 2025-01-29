/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { PaymenttermRequestCompound } from './paymentterm-request-compound';

/**
 * Request for POST /1/object/paymentterm
 * @export
 * @interface PaymenttermCreateObjectV1Request
 */
export interface PaymenttermCreateObjectV1Request {
    /**
     * 
     * @type {Array<PaymenttermRequestCompound>}
     * @memberof PaymenttermCreateObjectV1Request
     */
    /*'a_objPaymentterm': Array<PaymenttermRequestCompound>;*/
    'a_objPaymentterm': Array<PaymenttermRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PaymenttermCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermCreateObjectV1Request
 */
export class DataObjectPaymenttermCreateObjectV1Request {
   a_objPaymentterm:Array<PaymenttermRequestCompound> = []
}

/**
 * @export 
 * A PaymenttermCreateObjectV1Request Validation Object
 * @class ValidationObjectPaymenttermCreateObjectV1Request
 */
export class ValidationObjectPaymenttermCreateObjectV1Request {
   a_objPaymentterm = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


