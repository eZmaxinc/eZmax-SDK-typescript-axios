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
import { BillingentityexternalGetAutocompleteV2ResponseMPayload } from './billingentityexternal-get-autocomplete-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type BillingentityexternalGetAutocompleteV2Response
 * Response for GET /2/object/billingentityexternal/getAutocomplete
 * @export
 */
/** export type BillingentityexternalGetAutocompleteV2Response = CommonResponse; */
export interface BillingentityexternalGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof BillingentityexternalGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof BillingentityexternalGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {BillingentityexternalGetAutocompleteV2ResponseMPayload}
     * @memberof BillingentityexternalGetAutocompleteV2Response
     */
    mPayload:BillingentityexternalGetAutocompleteV2ResponseMPayload 
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
import { DataObjectBillingentityexternalGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectBillingentityexternalGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityexternalGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityexternalGetAutocompleteV2Response
 */
export class DataObjectBillingentityexternalGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:BillingentityexternalGetAutocompleteV2ResponseMPayload = new DataObjectBillingentityexternalGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A BillingentityexternalGetAutocompleteV2Response Validation Object
 * @class ValidationObjectBillingentityexternalGetAutocompleteV2Response
 */
export class ValidationObjectBillingentityexternalGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectBillingentityexternalGetAutocompleteV2ResponseMPayload()
} 

