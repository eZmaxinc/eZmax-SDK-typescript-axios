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
import type { BillingentityexternalGenerateFederationTokenV1ResponseMPayload } from './billingentityexternal-generate-federation-token-v1-response-mpayload';
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
 * @type BillingentityexternalGenerateFederationTokenV1Response
 * Response for POST /1/object/billingentityexternal/{pkiBillingentityexternalID}/generateFederationToken
 * @export
 */
/*export type BillingentityexternalGenerateFederationTokenV1Response = CommonResponse;*/
export interface BillingentityexternalGenerateFederationTokenV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof BillingentityexternalGenerateFederationTokenV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof BillingentityexternalGenerateFederationTokenV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {BillingentityexternalGenerateFederationTokenV1ResponseMPayload}
     * @memberof BillingentityexternalGenerateFederationTokenV1Response
     */
    mPayload:BillingentityexternalGenerateFederationTokenV1ResponseMPayload 
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
import { DataObjectBillingentityexternalGenerateFederationTokenV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectBillingentityexternalGenerateFederationTokenV1ResponseMPayload } from './'

/**
 * @export 
 * A BillingentityexternalGenerateFederationTokenV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityexternalGenerateFederationTokenV1Response
 */
export class DataObjectBillingentityexternalGenerateFederationTokenV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:BillingentityexternalGenerateFederationTokenV1ResponseMPayload = new DataObjectBillingentityexternalGenerateFederationTokenV1ResponseMPayload()
}

/**
 * @export 
 * A BillingentityexternalGenerateFederationTokenV1Response Validation Object
 * @class ValidationObjectBillingentityexternalGenerateFederationTokenV1Response
 */
export class ValidationObjectBillingentityexternalGenerateFederationTokenV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectBillingentityexternalGenerateFederationTokenV1ResponseMPayload()
} 


