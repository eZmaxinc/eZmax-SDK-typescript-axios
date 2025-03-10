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
import type { UserGetSubnetsV1ResponseMPayload } from './user-get-subnets-v1-response-mpayload';

/**
 * @type UserGetSubnetsV1Response
 * Response for GET /1/object/user/{pkiUserID}/getSubnets
 * @export
 */
/*export type UserGetSubnetsV1Response = CommonResponse;*/
export interface UserGetSubnetsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserGetSubnetsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserGetSubnetsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserGetSubnetsV1ResponseMPayload}
     * @memberof UserGetSubnetsV1Response
     */
    mPayload:UserGetSubnetsV1ResponseMPayload 
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
import { DataObjectUserGetSubnetsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserGetSubnetsV1ResponseMPayload } from './'

/**
 * @export 
 * A UserGetSubnetsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetSubnetsV1Response
 */
export class DataObjectUserGetSubnetsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserGetSubnetsV1ResponseMPayload = new DataObjectUserGetSubnetsV1ResponseMPayload()
}

/**
 * @export 
 * A UserGetSubnetsV1Response Validation Object
 * @class ValidationObjectUserGetSubnetsV1Response
 */
export class ValidationObjectUserGetSubnetsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserGetSubnetsV1ResponseMPayload()
} 


