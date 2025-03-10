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
import type { DiscussionGetObjectV2ResponseMPayload } from './discussion-get-object-v2-response-mpayload';

/**
 * @type DiscussionGetObjectV2Response
 * Response for GET /2/object/discussion/{pkiDiscussionID}
 * @export
 */
/*export type DiscussionGetObjectV2Response = CommonResponse;*/
export interface DiscussionGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof DiscussionGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof DiscussionGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {DiscussionGetObjectV2ResponseMPayload}
     * @memberof DiscussionGetObjectV2Response
     */
    mPayload:DiscussionGetObjectV2ResponseMPayload 
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
import { DataObjectDiscussionGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectDiscussionGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A DiscussionGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionGetObjectV2Response
 */
export class DataObjectDiscussionGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:DiscussionGetObjectV2ResponseMPayload = new DataObjectDiscussionGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A DiscussionGetObjectV2Response Validation Object
 * @class ValidationObjectDiscussionGetObjectV2Response
 */
export class ValidationObjectDiscussionGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectDiscussionGetObjectV2ResponseMPayload()
} 


