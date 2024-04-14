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
// May contain unused imports in some cases
// @ts-ignore
import { UserEditPermissionsV1ResponseMPayload } from './user-edit-permissions-v1-response-mpayload';

/**
 * @type UserEditPermissionsV1Response
 * Response for PUT /1/object/user/{pkiUserID}/editPermissions
 * @export
 */
/*export type UserEditPermissionsV1Response = CommonResponse;*/
export interface UserEditPermissionsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserEditPermissionsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserEditPermissionsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserEditPermissionsV1ResponseMPayload}
     * @memberof UserEditPermissionsV1Response
     */
    mPayload:UserEditPermissionsV1ResponseMPayload 
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
import { DataObjectUserEditPermissionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserEditPermissionsV1ResponseMPayload } from './'

/**
 * @export 
 * A UserEditPermissionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserEditPermissionsV1Response
 */
export class DataObjectUserEditPermissionsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserEditPermissionsV1ResponseMPayload = new DataObjectUserEditPermissionsV1ResponseMPayload()
}

/**
 * @export 
 * A UserEditPermissionsV1Response Validation Object
 * @class ValidationObjectUserEditPermissionsV1Response
 */
export class ValidationObjectUserEditPermissionsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserEditPermissionsV1ResponseMPayload()
} 


