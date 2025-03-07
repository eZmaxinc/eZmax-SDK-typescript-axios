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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { DiscussionCreateObjectV1ResponseMPayload } from './discussion-create-object-v1-response-mpayload';

/**
 * @type DiscussionCreateObjectV1Response
 * Response for POST /1/object/discussion
 * @export
 */
/*export type DiscussionCreateObjectV1Response = CommonResponse;*/
export interface DiscussionCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof DiscussionCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof DiscussionCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {DiscussionCreateObjectV1ResponseMPayload}
     * @memberof DiscussionCreateObjectV1Response
     */
    mPayload:DiscussionCreateObjectV1ResponseMPayload 
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
import { DataObjectDiscussionCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectDiscussionCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A DiscussionCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionCreateObjectV1Response
 */
export class DataObjectDiscussionCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:DiscussionCreateObjectV1ResponseMPayload = new DataObjectDiscussionCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A DiscussionCreateObjectV1Response Validation Object
 * @class ValidationObjectDiscussionCreateObjectV1Response
 */
export class ValidationObjectDiscussionCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectDiscussionCreateObjectV1ResponseMPayload()
} 


