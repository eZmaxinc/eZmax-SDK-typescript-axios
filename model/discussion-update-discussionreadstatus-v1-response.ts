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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type DiscussionUpdateDiscussionreadstatusV1Response
 * Response for GET /1/object/discussion/{pkiDiscussionID}/updateDiscussionreadstatus
 * @export
 */
/*export type DiscussionUpdateDiscussionreadstatusV1Response = CommonResponse;*/
export interface DiscussionUpdateDiscussionreadstatusV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof DiscussionUpdateDiscussionreadstatusV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof DiscussionUpdateDiscussionreadstatusV1Response
     */
    objDebug?:CommonResponseObjDebug 
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
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A DiscussionUpdateDiscussionreadstatusV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionUpdateDiscussionreadstatusV1Response
 */
export class DataObjectDiscussionUpdateDiscussionreadstatusV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A DiscussionUpdateDiscussionreadstatusV1Response Validation Object
 * @class ValidationObjectDiscussionUpdateDiscussionreadstatusV1Response
 */
export class ValidationObjectDiscussionUpdateDiscussionreadstatusV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


