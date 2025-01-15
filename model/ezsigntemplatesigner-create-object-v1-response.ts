/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
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
import type { EzsigntemplatesignerCreateObjectV1ResponseMPayload } from './ezsigntemplatesigner-create-object-v1-response-mpayload';

/**
 * @type EzsigntemplatesignerCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplatesigner
 * @export
 */
/*export type EzsigntemplatesignerCreateObjectV1Response = CommonResponse;*/
export interface EzsigntemplatesignerCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatesignerCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatesignerCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatesignerCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatesignerCreateObjectV1Response
     */
    mPayload:EzsigntemplatesignerCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsigntemplatesignerCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignerCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatesignerCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignerCreateObjectV1Response
 */
export class DataObjectEzsigntemplatesignerCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatesignerCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplatesignerCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatesignerCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatesignerCreateObjectV1Response
 */
export class ValidationObjectEzsigntemplatesignerCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatesignerCreateObjectV1ResponseMPayload()
} 


