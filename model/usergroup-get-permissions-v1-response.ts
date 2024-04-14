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
import { UsergroupGetPermissionsV1ResponseMPayload } from './usergroup-get-permissions-v1-response-mpayload';

/**
 * @type UsergroupGetPermissionsV1Response
 * Response for GET /1/object/usergroup/{pkiUsergroupID}/getPermissions
 * @export
 */
/*export type UsergroupGetPermissionsV1Response = CommonResponse;*/
export interface UsergroupGetPermissionsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UsergroupGetPermissionsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UsergroupGetPermissionsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UsergroupGetPermissionsV1ResponseMPayload}
     * @memberof UsergroupGetPermissionsV1Response
     */
    mPayload:UsergroupGetPermissionsV1ResponseMPayload 
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
import { DataObjectUsergroupGetPermissionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupGetPermissionsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupGetPermissionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetPermissionsV1Response
 */
export class DataObjectUsergroupGetPermissionsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupGetPermissionsV1ResponseMPayload = new DataObjectUsergroupGetPermissionsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupGetPermissionsV1Response Validation Object
 * @class ValidationObjectUsergroupGetPermissionsV1Response
 */
export class ValidationObjectUsergroupGetPermissionsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupGetPermissionsV1ResponseMPayload()
} 


