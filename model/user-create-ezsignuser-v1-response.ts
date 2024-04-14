/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
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
import { UserCreateEzsignuserV1ResponseMPayload } from './user-create-ezsignuser-v1-response-mpayload';

/**
 * @type UserCreateEzsignuserV1Response
 * Response for POST /1/module/user/createEzsignuser
 * @export
 */
/*export type UserCreateEzsignuserV1Response = CommonResponse;*/
export interface UserCreateEzsignuserV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserCreateEzsignuserV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserCreateEzsignuserV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserCreateEzsignuserV1ResponseMPayload}
     * @memberof UserCreateEzsignuserV1Response
     */
    mPayload:UserCreateEzsignuserV1ResponseMPayload 
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
import { DataObjectUserCreateEzsignuserV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserCreateEzsignuserV1ResponseMPayload } from './'

/**
 * @export 
 * A UserCreateEzsignuserV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserCreateEzsignuserV1Response
 */
export class DataObjectUserCreateEzsignuserV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserCreateEzsignuserV1ResponseMPayload = new DataObjectUserCreateEzsignuserV1ResponseMPayload()
}

/**
 * @export 
 * A UserCreateEzsignuserV1Response Validation Object
 * @class ValidationObjectUserCreateEzsignuserV1Response
 */
export class ValidationObjectUserCreateEzsignuserV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserCreateEzsignuserV1ResponseMPayload()
} 


