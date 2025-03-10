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
import type { UserGetColleaguesV2ResponseMPayload } from './user-get-colleagues-v2-response-mpayload';

/**
 * @type UserGetColleaguesV2Response
 * Response for GET /2/object/user/{pkiUserID}/getColleagues
 * @export
 */
/*export type UserGetColleaguesV2Response = CommonResponse;*/
export interface UserGetColleaguesV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserGetColleaguesV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserGetColleaguesV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserGetColleaguesV2ResponseMPayload}
     * @memberof UserGetColleaguesV2Response
     */
    mPayload:UserGetColleaguesV2ResponseMPayload 
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
import { DataObjectUserGetColleaguesV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserGetColleaguesV2ResponseMPayload } from './'

/**
 * @export 
 * A UserGetColleaguesV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetColleaguesV2Response
 */
export class DataObjectUserGetColleaguesV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserGetColleaguesV2ResponseMPayload = new DataObjectUserGetColleaguesV2ResponseMPayload()
}

/**
 * @export 
 * A UserGetColleaguesV2Response Validation Object
 * @class ValidationObjectUserGetColleaguesV2Response
 */
export class ValidationObjectUserGetColleaguesV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserGetColleaguesV2ResponseMPayload()
} 


