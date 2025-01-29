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
import type { EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload } from './ezsigntemplatedocument-edit-ezsigntemplatesignatures-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatesignatures
 * @export
 */
/*export type EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response
     */
    mPayload:EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload 
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
import { DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload = new DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1ResponseMPayload()
} 


