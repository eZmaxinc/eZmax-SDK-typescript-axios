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
import { PaymenttermResponseCompound } from './paymentterm-response-compound';

/**
 * Payload for GET /2/object/paymentterm/{pkiPaymenttermID}
 * @export
 * @interface PaymenttermGetObjectV2ResponseMPayload
 */
export interface PaymenttermGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {PaymenttermResponseCompound}
     * @memberof PaymenttermGetObjectV2ResponseMPayload
     */
    'objPaymentterm': PaymenttermResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectPaymenttermResponseCompound } from './'
// @ts-ignore
import { ValidationObjectPaymenttermResponseCompound } from './'

/**
 * @export 
 * A PaymenttermGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermGetObjectV2ResponseMPayload
 */
export class DataObjectPaymenttermGetObjectV2ResponseMPayload {
   objPaymentterm:PaymenttermResponseCompound = new DataObjectPaymenttermResponseCompound()
}

/**
 * @export 
 * A PaymenttermGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectPaymenttermGetObjectV2ResponseMPayload
 */
export class ValidationObjectPaymenttermGetObjectV2ResponseMPayload {
   objPaymentterm = new ValidationObjectPaymenttermResponseCompound()
} 

