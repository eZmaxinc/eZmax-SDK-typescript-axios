/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { UserstagedGetListV1ResponseAllOf } from './userstaged-get-list-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { UserstagedGetListV1ResponseMPayload } from './userstaged-get-list-v1-response-mpayload';

/**
 * @type UserstagedGetListV1Response
 * Response for GET /1/object/userstaged/getList
 * @export
 */
export type UserstagedGetListV1Response = CommonResponseGetList & UserstagedGetListV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserstagedGetListV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUserstagedGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A UserstagedGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserstagedGetListV1Response
 */
export class DataObjectUserstagedGetListV1Response {
    mPayload:UserstagedGetListV1ResponseMPayload = new DataObjectUserstagedGetListV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayloadGetList = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A UserstagedGetListV1Response Validation Object
 * @class ValidationObjectUserstagedGetListV1Response
 */
export class ValidationObjectUserstagedGetListV1Response {
   mPayload = new ValidationObjectUserstagedGetListV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


