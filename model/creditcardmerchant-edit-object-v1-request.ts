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
import type { CreditcardmerchantRequestCompound } from './creditcardmerchant-request-compound';

/**
 * Request for PUT /1/object/creditcardmerchant/{pkiCreditcardmerchantID}
 * @export
 * @interface CreditcardmerchantEditObjectV1Request
 */
export interface CreditcardmerchantEditObjectV1Request {
    /**
     * 
     * @type {CreditcardmerchantRequestCompound}
     * @memberof CreditcardmerchantEditObjectV1Request
     */
    /*'objCreditcardmerchant': CreditcardmerchantRequestCompound;*/
    'objCreditcardmerchant': CreditcardmerchantRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCreditcardmerchantRequestCompound } from './'
// @ts-ignore
import { ValidationObjectCreditcardmerchantRequestCompound } from './'

/**
 * @export 
 * A CreditcardmerchantEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardmerchantEditObjectV1Request
 */
export class DataObjectCreditcardmerchantEditObjectV1Request {
   objCreditcardmerchant:CreditcardmerchantRequestCompound = new DataObjectCreditcardmerchantRequestCompound()
}

/**
 * @export 
 * A CreditcardmerchantEditObjectV1Request Validation Object
 * @class ValidationObjectCreditcardmerchantEditObjectV1Request
 */
export class ValidationObjectCreditcardmerchantEditObjectV1Request {
   objCreditcardmerchant = new ValidationObjectCreditcardmerchantRequestCompound()
} 


