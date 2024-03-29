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
import { EzsignsignatureCreateObjectV1ResponseAllOf } from './ezsignsignature-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureCreateObjectV1ResponseMPayload } from './ezsignsignature-create-object-v1-response-mpayload';

/**
 * @type EzsignsignatureCreateObjectV1Response
 * Response for POST /1/object/ezsignsignature
 * @export
 */
export type EzsignsignatureCreateObjectV1Response = CommonResponse & EzsignsignatureCreateObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignsignatureCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureCreateObjectV1Response
 */
export class DataObjectEzsignsignatureCreateObjectV1Response {
    mPayload:EzsignsignatureCreateObjectV1ResponseMPayload = new DataObjectEzsignsignatureCreateObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignsignatureCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignsignatureCreateObjectV1Response
 */
export class ValidationObjectEzsignsignatureCreateObjectV1Response {
   mPayload = new ValidationObjectEzsignsignatureCreateObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


