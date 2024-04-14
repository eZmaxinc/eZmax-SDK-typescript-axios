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
import { UsergroupEditPermissionsV1ResponseMPayload } from './usergroup-edit-permissions-v1-response-mpayload';

/**
 * @type UsergroupEditPermissionsV1Response
 * Response for PUT /1/object/usergroup/{pkiUsergroupID}/editPermissions
 * @export
 */
/*export type UsergroupEditPermissionsV1Response = CommonResponse;*/
export interface UsergroupEditPermissionsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UsergroupEditPermissionsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UsergroupEditPermissionsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UsergroupEditPermissionsV1ResponseMPayload}
     * @memberof UsergroupEditPermissionsV1Response
     */
    mPayload:UsergroupEditPermissionsV1ResponseMPayload 
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
import { DataObjectUsergroupEditPermissionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupEditPermissionsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupEditPermissionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditPermissionsV1Response
 */
export class DataObjectUsergroupEditPermissionsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupEditPermissionsV1ResponseMPayload = new DataObjectUsergroupEditPermissionsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupEditPermissionsV1Response Validation Object
 * @class ValidationObjectUsergroupEditPermissionsV1Response
 */
export class ValidationObjectUsergroupEditPermissionsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupEditPermissionsV1ResponseMPayload()
} 


