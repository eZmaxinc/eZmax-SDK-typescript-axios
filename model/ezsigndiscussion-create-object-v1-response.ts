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
import type { EzsigndiscussionCreateObjectV1ResponseMPayload } from './ezsigndiscussion-create-object-v1-response-mpayload';

/**
 * @type EzsigndiscussionCreateObjectV1Response
 * Response for POST /1/object/ezsigndiscussion
 * @export
 */
/*export type EzsigndiscussionCreateObjectV1Response = CommonResponse;*/
export interface EzsigndiscussionCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndiscussionCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndiscussionCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndiscussionCreateObjectV1ResponseMPayload}
     * @memberof EzsigndiscussionCreateObjectV1Response
     */
    mPayload:EzsigndiscussionCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsigndiscussionCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndiscussionCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndiscussionCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndiscussionCreateObjectV1Response
 */
export class DataObjectEzsigndiscussionCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndiscussionCreateObjectV1ResponseMPayload = new DataObjectEzsigndiscussionCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndiscussionCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigndiscussionCreateObjectV1Response
 */
export class ValidationObjectEzsigndiscussionCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndiscussionCreateObjectV1ResponseMPayload()
} 


