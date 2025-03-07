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
import type { UserGetEffectivePermissionsV1ResponseMPayload } from './user-get-effective-permissions-v1-response-mpayload';

/**
 * @type UserGetEffectivePermissionsV1Response
 * Response for GET /1/object/user/{pkiUserID}/getEffectivePermissions
 * @export
 */
/*export type UserGetEffectivePermissionsV1Response = CommonResponse;*/
export interface UserGetEffectivePermissionsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserGetEffectivePermissionsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserGetEffectivePermissionsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserGetEffectivePermissionsV1ResponseMPayload}
     * @memberof UserGetEffectivePermissionsV1Response
     */
    mPayload:UserGetEffectivePermissionsV1ResponseMPayload 
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
import { DataObjectUserGetEffectivePermissionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserGetEffectivePermissionsV1ResponseMPayload } from './'

/**
 * @export 
 * A UserGetEffectivePermissionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetEffectivePermissionsV1Response
 */
export class DataObjectUserGetEffectivePermissionsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserGetEffectivePermissionsV1ResponseMPayload = new DataObjectUserGetEffectivePermissionsV1ResponseMPayload()
}

/**
 * @export 
 * A UserGetEffectivePermissionsV1Response Validation Object
 * @class ValidationObjectUserGetEffectivePermissionsV1Response
 */
export class ValidationObjectUserGetEffectivePermissionsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserGetEffectivePermissionsV1ResponseMPayload()
} 


