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
import { EzsigntemplatesignatureCreateObjectV1ResponseMPayload } from './ezsigntemplatesignature-create-object-v1-response-mpayload';

/**
 * @type EzsigntemplatesignatureCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplatesignature
 * @export
 */
/*export type EzsigntemplatesignatureCreateObjectV1Response = CommonResponse;*/
export interface EzsigntemplatesignatureCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatesignatureCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatesignatureCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatesignatureCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatesignatureCreateObjectV1Response
     */
    mPayload:EzsigntemplatesignatureCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsigntemplatesignatureCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignatureCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatesignatureCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureCreateObjectV1Response
 */
export class DataObjectEzsigntemplatesignatureCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatesignatureCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplatesignatureCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatesignatureCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatesignatureCreateObjectV1Response
 */
export class ValidationObjectEzsigntemplatesignatureCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatesignatureCreateObjectV1ResponseMPayload()
} 


