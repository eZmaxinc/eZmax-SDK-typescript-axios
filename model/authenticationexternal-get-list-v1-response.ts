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
import type { AuthenticationexternalGetListV1ResponseMPayload } from './authenticationexternal-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';

/**
 * @type AuthenticationexternalGetListV1Response
 * Response for GET /1/object/authenticationexternal/getList
 * @export
 */
/*export type AuthenticationexternalGetListV1Response = CommonResponseGetList;*/
export interface AuthenticationexternalGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof AuthenticationexternalGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof AuthenticationexternalGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {AuthenticationexternalGetListV1ResponseMPayload}
     * @memberof AuthenticationexternalGetListV1Response
     */
    mPayload:AuthenticationexternalGetListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectAuthenticationexternalGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectAuthenticationexternalGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A AuthenticationexternalGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAuthenticationexternalGetListV1Response
 */
export class DataObjectAuthenticationexternalGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:AuthenticationexternalGetListV1ResponseMPayload = new DataObjectAuthenticationexternalGetListV1ResponseMPayload()
}

/**
 * @export 
 * A AuthenticationexternalGetListV1Response Validation Object
 * @class ValidationObjectAuthenticationexternalGetListV1Response
 */
export class ValidationObjectAuthenticationexternalGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectAuthenticationexternalGetListV1ResponseMPayload()
} 


