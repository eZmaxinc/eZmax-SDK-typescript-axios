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
import type { ModulegroupGetAllV1ResponseMPayload } from './modulegroup-get-all-v1-response-mpayload';

/**
 * @type ModulegroupGetAllV1Response
 * Response for GET /1/object/modulegroup/getAll
 * @export
 */
/*export type ModulegroupGetAllV1Response = CommonResponse;*/
export interface ModulegroupGetAllV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ModulegroupGetAllV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ModulegroupGetAllV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ModulegroupGetAllV1ResponseMPayload}
     * @memberof ModulegroupGetAllV1Response
     */
    mPayload:ModulegroupGetAllV1ResponseMPayload 
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
import { DataObjectModulegroupGetAllV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectModulegroupGetAllV1ResponseMPayload } from './'

/**
 * @export 
 * A ModulegroupGetAllV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModulegroupGetAllV1Response
 */
export class DataObjectModulegroupGetAllV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ModulegroupGetAllV1ResponseMPayload = new DataObjectModulegroupGetAllV1ResponseMPayload()
}

/**
 * @export 
 * A ModulegroupGetAllV1Response Validation Object
 * @class ValidationObjectModulegroupGetAllV1Response
 */
export class ValidationObjectModulegroupGetAllV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectModulegroupGetAllV1ResponseMPayload()
} 


