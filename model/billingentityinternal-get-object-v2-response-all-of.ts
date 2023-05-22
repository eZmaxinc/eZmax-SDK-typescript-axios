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
import { BillingentityinternalGetObjectV2ResponseMPayload } from './billingentityinternal-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface BillingentityinternalGetObjectV2ResponseAllOf
 */
export interface BillingentityinternalGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {BillingentityinternalGetObjectV2ResponseMPayload}
     * @memberof BillingentityinternalGetObjectV2ResponseAllOf
     */
    'mPayload': BillingentityinternalGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBillingentityinternalGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityinternalGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalGetObjectV2ResponseAllOf
 */
export class DataObjectBillingentityinternalGetObjectV2ResponseAllOf {
   mPayload:BillingentityinternalGetObjectV2ResponseMPayload = new DataObjectBillingentityinternalGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A BillingentityinternalGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectBillingentityinternalGetObjectV2ResponseAllOf
 */
export class ValidationObjectBillingentityinternalGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectBillingentityinternalGetObjectV2ResponseMPayload()
} 


