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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupexternalGetListV1ResponseMPayload } from './usergroupexternal-get-list-v1-response-mpayload';

/**
 * @type UsergroupexternalGetListV1Response
 * Response for GET /1/object/usergroupexternal/getList
 * @export
 */
/*export type UsergroupexternalGetListV1Response = CommonResponseGetList;*/
export interface UsergroupexternalGetListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof UsergroupexternalGetListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UsergroupexternalGetListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UsergroupexternalGetListV1ResponseMPayload}
     * @memberof UsergroupexternalGetListV1Response
     */
    mPayload:UsergroupexternalGetListV1ResponseMPayload 
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
import { DataObjectUsergroupexternalGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupexternalGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupexternalGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetListV1Response
 */
export class DataObjectUsergroupexternalGetListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupexternalGetListV1ResponseMPayload = new DataObjectUsergroupexternalGetListV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupexternalGetListV1Response Validation Object
 * @class ValidationObjectUsergroupexternalGetListV1Response
 */
export class ValidationObjectUsergroupexternalGetListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupexternalGetListV1ResponseMPayload()
} 


