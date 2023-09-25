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
import { ApikeyEditPermissionsV1ResponseMPayload } from './apikey-edit-permissions-v1-response-mpayload';
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
 * @type ApikeyEditPermissionsV1Response
 * Response for PUT /1/object/apikey/{pkiApikeyID}/editPermissions
 * @export
 */
/** export type ApikeyEditPermissionsV1Response = CommonResponse; */
export interface ApikeyEditPermissionsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ApikeyEditPermissionsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ApikeyEditPermissionsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ApikeyEditPermissionsV1ResponseMPayload}
     * @memberof ApikeyEditPermissionsV1Response
     */
    mPayload:ApikeyEditPermissionsV1ResponseMPayload 
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
import { DataObjectApikeyEditPermissionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectApikeyEditPermissionsV1ResponseMPayload } from './'

/**
 * @export 
 * A ApikeyEditPermissionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyEditPermissionsV1Response
 */
export class DataObjectApikeyEditPermissionsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ApikeyEditPermissionsV1ResponseMPayload = new DataObjectApikeyEditPermissionsV1ResponseMPayload()
}

/**
 * @export 
 * A ApikeyEditPermissionsV1Response Validation Object
 * @class ValidationObjectApikeyEditPermissionsV1Response
 */
export class ValidationObjectApikeyEditPermissionsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectApikeyEditPermissionsV1ResponseMPayload()
} 


