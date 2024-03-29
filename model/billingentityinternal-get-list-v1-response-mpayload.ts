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
import { BillingentityinternalGetListV1ResponseMPayloadAllOf } from './billingentityinternal-get-list-v1-response-mpayload-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { BillingentityinternalListElement } from './billingentityinternal-list-element';
// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';

/**
 * @type BillingentityinternalGetListV1ResponseMPayload
 * Payload for GET /1/object/billingentityinternal/getList
 * @export
 */
export type BillingentityinternalGetListV1ResponseMPayload = BillingentityinternalGetListV1ResponseMPayloadAllOf & CommonGetListV1ResponseMPayload;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BillingentityinternalGetListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalGetListV1ResponseMPayload
 */
export class DataObjectBillingentityinternalGetListV1ResponseMPayload {
    a_objBillingentityinternal:Array<BillingentityinternalListElement> = []
    iRowReturned:number = 0
    iRowFiltered:number = 0
}

/**
 * @export 
 * A BillingentityinternalGetListV1ResponseMPayload Validation Object
 * @class ValidationObjectBillingentityinternalGetListV1ResponseMPayload
 */
export class ValidationObjectBillingentityinternalGetListV1ResponseMPayload {
   a_objBillingentityinternal = {
      type: 'array',
      required: true
   }
   iRowReturned = {
      type: 'integer',
      required: true
   }
   iRowFiltered = {
      type: 'integer',
      required: true
   }
} 


