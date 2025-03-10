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
import type { BillingentityinternalCreateObjectV1ResponseMPayload } from './billingentityinternal-create-object-v1-response-mpayload';
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
 * @type BillingentityinternalCreateObjectV1Response
 * Response for POST /1/object/billingentityinternal
 * @export
 */
/*export type BillingentityinternalCreateObjectV1Response = CommonResponse;*/
export interface BillingentityinternalCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof BillingentityinternalCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof BillingentityinternalCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {BillingentityinternalCreateObjectV1ResponseMPayload}
     * @memberof BillingentityinternalCreateObjectV1Response
     */
    mPayload:BillingentityinternalCreateObjectV1ResponseMPayload 
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
import { DataObjectBillingentityinternalCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityinternalCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalCreateObjectV1Response
 */
export class DataObjectBillingentityinternalCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:BillingentityinternalCreateObjectV1ResponseMPayload = new DataObjectBillingentityinternalCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A BillingentityinternalCreateObjectV1Response Validation Object
 * @class ValidationObjectBillingentityinternalCreateObjectV1Response
 */
export class ValidationObjectBillingentityinternalCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectBillingentityinternalCreateObjectV1ResponseMPayload()
} 


