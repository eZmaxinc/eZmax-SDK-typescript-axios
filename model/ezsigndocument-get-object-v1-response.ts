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
import type { EzsigndocumentGetObjectV1ResponseMPayload } from './ezsigndocument-get-object-v1-response-mpayload';

/**
 * @type EzsigndocumentGetObjectV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}
 * @export
 */
/*export type EzsigndocumentGetObjectV1Response = CommonResponse;*/
export interface EzsigndocumentGetObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentGetObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentGetObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndocumentGetObjectV1ResponseMPayload}
     * @memberof EzsigndocumentGetObjectV1Response
     */
    mPayload:EzsigndocumentGetObjectV1ResponseMPayload 
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
import { DataObjectEzsigndocumentGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetObjectV1Response
 */
export class DataObjectEzsigndocumentGetObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndocumentGetObjectV1ResponseMPayload = new DataObjectEzsigndocumentGetObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetObjectV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetObjectV1Response
 */
export class ValidationObjectEzsigndocumentGetObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndocumentGetObjectV1ResponseMPayload()
} 


