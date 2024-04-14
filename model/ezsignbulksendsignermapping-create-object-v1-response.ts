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
import { EzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './ezsignbulksendsignermapping-create-object-v1-response-mpayload';

/**
 * @type EzsignbulksendsignermappingCreateObjectV1Response
 * Response for POST /1/object/ezsignbulksendsignermapping
 * @export
 */
/*export type EzsignbulksendsignermappingCreateObjectV1Response = CommonResponse;*/
export interface EzsignbulksendsignermappingCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendsignermappingCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendsignermappingCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendsignermappingCreateObjectV1ResponseMPayload}
     * @memberof EzsignbulksendsignermappingCreateObjectV1Response
     */
    mPayload:EzsignbulksendsignermappingCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendsignermappingCreateObjectV1Response
 */
export class DataObjectEzsignbulksendsignermappingCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendsignermappingCreateObjectV1ResponseMPayload = new DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignbulksendsignermappingCreateObjectV1Response
 */
export class ValidationObjectEzsignbulksendsignermappingCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload()
} 


