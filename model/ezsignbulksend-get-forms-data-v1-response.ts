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
import { EzsignbulksendGetFormsDataV1ResponseMPayload } from './ezsignbulksend-get-forms-data-v1-response-mpayload';

/**
 * @type EzsignbulksendGetFormsDataV1Response
 * Response for GET /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getFormsData
 * @export
 */
/** export type EzsignbulksendGetFormsDataV1Response = CommonResponse; */
export interface EzsignbulksendGetFormsDataV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendGetFormsDataV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendGetFormsDataV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendGetFormsDataV1ResponseMPayload}
     * @memberof EzsignbulksendGetFormsDataV1Response
     */
    mPayload:EzsignbulksendGetFormsDataV1ResponseMPayload 
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
import { DataObjectEzsignbulksendGetFormsDataV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendGetFormsDataV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendGetFormsDataV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendGetFormsDataV1Response
 */
export class DataObjectEzsignbulksendGetFormsDataV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendGetFormsDataV1ResponseMPayload = new DataObjectEzsignbulksendGetFormsDataV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendGetFormsDataV1Response Validation Object
 * @class ValidationObjectEzsignbulksendGetFormsDataV1Response
 */
export class ValidationObjectEzsignbulksendGetFormsDataV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendGetFormsDataV1ResponseMPayload()
} 


