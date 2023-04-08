/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionGetListV1ResponseAllOf } from './activesession-get-list-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionGetListV1ResponseMPayload } from './activesession-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';

/**
 * @type ActivesessionGetListV1Response
 * Response for GET /1/object/activesession/getList
 * @export
 */
export type ActivesessionGetListV1Response = ActivesessionGetListV1ResponseAllOf & CommonResponseGetList;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectActivesessionGetListV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectActivesessionGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A ActivesessionGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionGetListV1Response
 */
export class DataObjectActivesessionGetListV1Response {
   mPayload:ActivesessionGetListV1ResponseMPayload = new DataObjectActivesessionGetListV1ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayloadGetList = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A ActivesessionGetListV1Response Validation Object
 * @class ValidationObjectActivesessionGetListV1Response
 */
export class ValidationObjectActivesessionGetListV1Response {
   mPayload = new ValidationObjectActivesessionGetListV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


