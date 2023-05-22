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
import { BillingentityinternalGetListV1ResponseMPayload } from './billingentityinternal-get-list-v1-response-mpayload';

/**
 * 
 * @export
 * @interface BillingentityinternalGetListV1ResponseAllOf
 */
export interface BillingentityinternalGetListV1ResponseAllOf {
    /**
     * 
     * @type {BillingentityinternalGetListV1ResponseMPayload}
     * @memberof BillingentityinternalGetListV1ResponseAllOf
     */
    'mPayload': BillingentityinternalGetListV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBillingentityinternalGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityinternalGetListV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalGetListV1ResponseAllOf
 */
export class DataObjectBillingentityinternalGetListV1ResponseAllOf {
   mPayload:BillingentityinternalGetListV1ResponseMPayload = new DataObjectBillingentityinternalGetListV1ResponseMPayload()
}

/**
 * @export 
 * A BillingentityinternalGetListV1ResponseAllOf Validation Object
 * @class ValidationObjectBillingentityinternalGetListV1ResponseAllOf
 */
export class ValidationObjectBillingentityinternalGetListV1ResponseAllOf {
   mPayload = new ValidationObjectBillingentityinternalGetListV1ResponseMPayload()
} 


