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
import { EzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf } from './ezsignbulksenddocumentmapping-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './ezsignbulksenddocumentmapping-create-object-v1-response-mpayload';

/**
 * @type EzsignbulksenddocumentmappingCreateObjectV1Response
 * Response for POST /1/object/ezsignbulksenddocumentmapping
 * @export
 */
export type EzsignbulksenddocumentmappingCreateObjectV1Response = CommonResponse & EzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingCreateObjectV1Response
 */
export class DataObjectEzsignbulksenddocumentmappingCreateObjectV1Response {
    mPayload:EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload = new DataObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1Response
 */
export class ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1Response {
   mPayload = new ValidationObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


