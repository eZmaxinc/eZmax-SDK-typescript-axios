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
import { UserGetUsergroupexternalsV1ResponseMPayload } from './user-get-usergroupexternals-v1-response-mpayload';

/**
 * @type UserGetUsergroupexternalsV1Response
 * Response for GET /1/object/user/{pkiUserID}/getUsergroupexternals
 * @export
 */
/** export type UserGetUsergroupexternalsV1Response = CommonResponse; */
export interface UserGetUsergroupexternalsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UserGetUsergroupexternalsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UserGetUsergroupexternalsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UserGetUsergroupexternalsV1ResponseMPayload}
     * @memberof UserGetUsergroupexternalsV1Response
     */
    mPayload:UserGetUsergroupexternalsV1ResponseMPayload 
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
import { DataObjectUserGetUsergroupexternalsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserGetUsergroupexternalsV1ResponseMPayload } from './'

/**
 * @export 
 * A UserGetUsergroupexternalsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetUsergroupexternalsV1Response
 */
export class DataObjectUserGetUsergroupexternalsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UserGetUsergroupexternalsV1ResponseMPayload = new DataObjectUserGetUsergroupexternalsV1ResponseMPayload()
}

/**
 * @export 
 * A UserGetUsergroupexternalsV1Response Validation Object
 * @class ValidationObjectUserGetUsergroupexternalsV1Response
 */
export class ValidationObjectUserGetUsergroupexternalsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUserGetUsergroupexternalsV1ResponseMPayload()
} 


