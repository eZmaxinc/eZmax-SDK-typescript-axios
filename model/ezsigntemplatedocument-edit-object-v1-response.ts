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
import type { CommonResponseWarning } from './common-response-warning';

/**
 * @type EzsigntemplatedocumentEditObjectV1Response
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}
 * @export
 */
/*export type EzsigntemplatedocumentEditObjectV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentEditObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatedocumentEditObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatedocumentEditObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {Array<CommonResponseWarning>}
     * @memberof EzsigntemplatedocumentEditObjectV1Response
     */
    a_objWarning?:Array<CommonResponseWarning> 
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
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplatedocumentEditObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditObjectV1Response
 */
export class DataObjectEzsigntemplatedocumentEditObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    a_objWarning?:Array<CommonResponseWarning> = undefined
}

/**
 * @export 
 * A EzsigntemplatedocumentEditObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditObjectV1Response
 */
export class ValidationObjectEzsigntemplatedocumentEditObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   a_objWarning = {
      type: 'array',
      required: false
   }
} 


