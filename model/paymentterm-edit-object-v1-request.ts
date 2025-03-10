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
import type { PaymenttermRequestCompound } from './paymentterm-request-compound';

/**
 * Request for PUT /1/object/paymentterm/{pkiPaymenttermID}
 * @export
 * @interface PaymenttermEditObjectV1Request
 */
export interface PaymenttermEditObjectV1Request {
    /**
     * 
     * @type {PaymenttermRequestCompound}
     * @memberof PaymenttermEditObjectV1Request
     */
    /*'objPaymentterm': PaymenttermRequestCompound;*/
    'objPaymentterm': PaymenttermRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectPaymenttermRequestCompound } from './'
// @ts-ignore
import { ValidationObjectPaymenttermRequestCompound } from './'

/**
 * @export 
 * A PaymenttermEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermEditObjectV1Request
 */
export class DataObjectPaymenttermEditObjectV1Request {
   objPaymentterm:PaymenttermRequestCompound = new DataObjectPaymenttermRequestCompound()
}

/**
 * @export 
 * A PaymenttermEditObjectV1Request Validation Object
 * @class ValidationObjectPaymenttermEditObjectV1Request
 */
export class ValidationObjectPaymenttermEditObjectV1Request {
   objPaymentterm = new ValidationObjectPaymenttermRequestCompound()
} 


