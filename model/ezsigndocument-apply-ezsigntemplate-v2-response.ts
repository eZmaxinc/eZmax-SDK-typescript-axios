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
import type { CommonResponseWarning } from './common-response-warning';

/**
 * @type EzsigndocumentApplyEzsigntemplateV2Response
 * Response for POST /2/object/ezsigndocument/{pkiEzsigndocument}/applyEzsigntemplate
 * @export
 */
/*export type EzsigndocumentApplyEzsigntemplateV2Response = CommonResponse;*/
export interface EzsigndocumentApplyEzsigntemplateV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {Array<CommonResponseWarning>}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Response
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
 * A EzsigndocumentApplyEzsigntemplateV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentApplyEzsigntemplateV2Response
 */
export class DataObjectEzsigndocumentApplyEzsigntemplateV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    a_objWarning?:Array<CommonResponseWarning> = undefined
}

/**
 * @export 
 * A EzsigndocumentApplyEzsigntemplateV2Response Validation Object
 * @class ValidationObjectEzsigndocumentApplyEzsigntemplateV2Response
 */
export class ValidationObjectEzsigndocumentApplyEzsigntemplateV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   a_objWarning = {
      type: 'array',
      required: false
   }
} 


