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
import { BillingentityinternalRequestCompound } from './billingentityinternal-request-compound';

/**
 * Request for PUT /1/object/billingentityinternal/{pkiBillingentityinternalID}
 * @export
 * @interface BillingentityinternalEditObjectV1Request
 */
export interface BillingentityinternalEditObjectV1Request {
    /**
     * 
     * @type {BillingentityinternalRequestCompound}
     * @memberof BillingentityinternalEditObjectV1Request
     */
    'objBillingentityinternal': BillingentityinternalRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBillingentityinternalRequestCompound } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalRequestCompound } from './'

/**
 * @export 
 * A BillingentityinternalEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalEditObjectV1Request
 */
export class DataObjectBillingentityinternalEditObjectV1Request {
   objBillingentityinternal:BillingentityinternalRequestCompound = new DataObjectBillingentityinternalRequestCompound()
}

/**
 * @export 
 * A BillingentityinternalEditObjectV1Request Validation Object
 * @class ValidationObjectBillingentityinternalEditObjectV1Request
 */
export class ValidationObjectBillingentityinternalEditObjectV1Request {
   objBillingentityinternal = new ValidationObjectBillingentityinternalRequestCompound()
} 


