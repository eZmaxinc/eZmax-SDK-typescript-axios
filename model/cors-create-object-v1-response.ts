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
import { CorsCreateObjectV1ResponseMPayload } from './cors-create-object-v1-response-mpayload';

/**
 * @type CorsCreateObjectV1Response
 * Response for POST /1/object/cors
 * @export
 */
/** export type CorsCreateObjectV1Response = CommonResponse; */
export interface CorsCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CorsCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CorsCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {CorsCreateObjectV1ResponseMPayload}
     * @memberof CorsCreateObjectV1Response
     */
    mPayload:CorsCreateObjectV1ResponseMPayload 
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
import { DataObjectCorsCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectCorsCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A CorsCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCorsCreateObjectV1Response
 */
export class DataObjectCorsCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:CorsCreateObjectV1ResponseMPayload = new DataObjectCorsCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A CorsCreateObjectV1Response Validation Object
 * @class ValidationObjectCorsCreateObjectV1Response
 */
export class ValidationObjectCorsCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectCorsCreateObjectV1ResponseMPayload()
} 


