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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupCreateObjectV1ResponseAllOf } from './usergroup-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupCreateObjectV1ResponseMPayload } from './usergroup-create-object-v1-response-mpayload';

/**
 * @type UsergroupCreateObjectV1Response
 * Response for POST /1/object/usergroup
 * @export
 */
export type UsergroupCreateObjectV1Response = CommonResponse & UsergroupCreateObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A UsergroupCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupCreateObjectV1Response
 */
export class DataObjectUsergroupCreateObjectV1Response {
    mPayload:UsergroupCreateObjectV1ResponseMPayload = new DataObjectUsergroupCreateObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A UsergroupCreateObjectV1Response Validation Object
 * @class ValidationObjectUsergroupCreateObjectV1Response
 */
export class ValidationObjectUsergroupCreateObjectV1Response {
   mPayload = new ValidationObjectUsergroupCreateObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


