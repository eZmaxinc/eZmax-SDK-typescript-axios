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
import { ApikeyGetListV1ResponseAllOf } from './apikey-get-list-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { ApikeyGetListV1ResponseMPayload } from './apikey-get-list-v1-response-mpayload';
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
 * @type ApikeyGetListV1Response
 * Response for GET /1/object/apikey/getList
 * @export
 */
export type ApikeyGetListV1Response = ApikeyGetListV1ResponseAllOf & CommonResponseGetList;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectApikeyGetListV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectApikeyGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A ApikeyGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyGetListV1Response
 */
export class DataObjectApikeyGetListV1Response {
    mPayload:ApikeyGetListV1ResponseMPayload = new DataObjectApikeyGetListV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayloadGetList = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A ApikeyGetListV1Response Validation Object
 * @class ValidationObjectApikeyGetListV1Response
 */
export class ValidationObjectApikeyGetListV1Response {
   mPayload = new ValidationObjectApikeyGetListV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


