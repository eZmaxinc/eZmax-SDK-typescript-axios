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
import type { UserstagedGetObjectV2ResponseMPayload } from './userstaged-get-object-v2-response-mpayload';

/**
 * @type UserstagedGetObjectV2Response
 * Response for GET /2/object/userstaged/{pkiUserstagedID}
 * @export
 */
/*export type UserstagedGetObjectV2Response = CommonResponse;*/
export interface UserstagedGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserstagedGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserstagedGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserstagedGetObjectV2ResponseMPayload}
     * @memberof UserstagedGetObjectV2Response
     */
    mPayload:UserstagedGetObjectV2ResponseMPayload 
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
import { DataObjectUserstagedGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserstagedGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A UserstagedGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedGetObjectV2Response
 */
export class DataObjectUserstagedGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserstagedGetObjectV2ResponseMPayload = new DataObjectUserstagedGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A UserstagedGetObjectV2Response Validation Object
 * @class ValidationObjectUserstagedGetObjectV2Response
 */
export class ValidationObjectUserstagedGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserstagedGetObjectV2ResponseMPayload()
} 


