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
import { EzsignbulksendsignermappingCreateObjectV1ResponseAllOf } from './ezsignbulksendsignermapping-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './ezsignbulksendsignermapping-create-object-v1-response-mpayload';

/**
 * @type EzsignbulksendsignermappingCreateObjectV1Response
 * Response for POST /1/object/ezsignbulksendsignermapping
 * @export
 */
export type EzsignbulksendsignermappingCreateObjectV1Response = CommonResponse & EzsignbulksendsignermappingCreateObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendsignermappingCreateObjectV1Response
 */
export class DataObjectEzsignbulksendsignermappingCreateObjectV1Response {
    mPayload:EzsignbulksendsignermappingCreateObjectV1ResponseMPayload = new DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignbulksendsignermappingCreateObjectV1Response
 */
export class ValidationObjectEzsignbulksendsignermappingCreateObjectV1Response {
   mPayload = new ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


