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
import type { EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './ezsignbulksenddocumentmapping-create-object-v1-response-mpayload';

/**
 * @type EzsignbulksenddocumentmappingCreateObjectV1Response
 * Response for POST /1/object/ezsignbulksenddocumentmapping
 * @export
 */
/*export type EzsignbulksenddocumentmappingCreateObjectV1Response = CommonResponse;*/
export interface EzsignbulksenddocumentmappingCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1Response
     */
    mPayload:EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingCreateObjectV1Response
 */
export class DataObjectEzsignbulksenddocumentmappingCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload = new DataObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1Response
 */
export class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload()
} 


