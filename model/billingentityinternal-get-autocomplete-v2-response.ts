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
import type { BillingentityinternalGetAutocompleteV2ResponseMPayload } from './billingentityinternal-get-autocomplete-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type BillingentityinternalGetAutocompleteV2Response
 * Response for GET /2/object/billingentityinternal/getAutocomplete
 * @export
 */
/*export type BillingentityinternalGetAutocompleteV2Response = CommonResponse;*/
export interface BillingentityinternalGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof BillingentityinternalGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof BillingentityinternalGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {BillingentityinternalGetAutocompleteV2ResponseMPayload}
     * @memberof BillingentityinternalGetAutocompleteV2Response
     */
    mPayload:BillingentityinternalGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectBillingentityinternalGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityinternalGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalGetAutocompleteV2Response
 */
export class DataObjectBillingentityinternalGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:BillingentityinternalGetAutocompleteV2ResponseMPayload = new DataObjectBillingentityinternalGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A BillingentityinternalGetAutocompleteV2Response Validation Object
 * @class ValidationObjectBillingentityinternalGetAutocompleteV2Response
 */
export class ValidationObjectBillingentityinternalGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectBillingentityinternalGetAutocompleteV2ResponseMPayload()
} 


