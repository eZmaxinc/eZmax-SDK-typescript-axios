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
import type { PermissionGetObjectV2ResponseMPayload } from './permission-get-object-v2-response-mpayload';

/**
 * @type PermissionGetObjectV2Response
 * Response for GET /2/object/permission/{pkiPermissionID}
 * @export
 */
/*export type PermissionGetObjectV2Response = CommonResponse;*/
export interface PermissionGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof PermissionGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof PermissionGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {PermissionGetObjectV2ResponseMPayload}
     * @memberof PermissionGetObjectV2Response
     */
    mPayload:PermissionGetObjectV2ResponseMPayload 
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
import { DataObjectPermissionGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectPermissionGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A PermissionGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPermissionGetObjectV2Response
 */
export class DataObjectPermissionGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:PermissionGetObjectV2ResponseMPayload = new DataObjectPermissionGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A PermissionGetObjectV2Response Validation Object
 * @class ValidationObjectPermissionGetObjectV2Response
 */
export class ValidationObjectPermissionGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectPermissionGetObjectV2ResponseMPayload()
} 


