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
import type { BillingentityinternalGetObjectV2ResponseMPayload } from './billingentityinternal-get-object-v2-response-mpayload';
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
 * @type BillingentityinternalGetObjectV2Response
 * Response for GET /2/object/billingentityinternal/{pkiBillingentityinternalID}
 * @export
 */
/*export type BillingentityinternalGetObjectV2Response = CommonResponse;*/
export interface BillingentityinternalGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof BillingentityinternalGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof BillingentityinternalGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {BillingentityinternalGetObjectV2ResponseMPayload}
     * @memberof BillingentityinternalGetObjectV2Response
     */
    mPayload:BillingentityinternalGetObjectV2ResponseMPayload 
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
import { DataObjectBillingentityinternalGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityinternalGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalGetObjectV2Response
 */
export class DataObjectBillingentityinternalGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:BillingentityinternalGetObjectV2ResponseMPayload = new DataObjectBillingentityinternalGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A BillingentityinternalGetObjectV2Response Validation Object
 * @class ValidationObjectBillingentityinternalGetObjectV2Response
 */
export class ValidationObjectBillingentityinternalGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectBillingentityinternalGetObjectV2ResponseMPayload()
} 


