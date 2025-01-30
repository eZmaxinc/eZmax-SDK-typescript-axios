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
import type { EzsigndocumentCreateObjectV3ResponseMPayload } from './ezsigndocument-create-object-v3-response-mpayload';

/**
 * @type EzsigndocumentCreateObjectV3Response
 * Response for POST /3/object/ezsigndocument
 * @export
 */
/*export type EzsigndocumentCreateObjectV3Response = CommonResponse;*/
export interface EzsigndocumentCreateObjectV3Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentCreateObjectV3Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentCreateObjectV3Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndocumentCreateObjectV3ResponseMPayload}
     * @memberof EzsigndocumentCreateObjectV3Response
     */
    mPayload:EzsigndocumentCreateObjectV3ResponseMPayload 
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
import { DataObjectEzsigndocumentCreateObjectV3ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentCreateObjectV3ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentCreateObjectV3Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentCreateObjectV3Response
 */
export class DataObjectEzsigndocumentCreateObjectV3Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndocumentCreateObjectV3ResponseMPayload = new DataObjectEzsigndocumentCreateObjectV3ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentCreateObjectV3Response Validation Object
 * @class ValidationObjectEzsigndocumentCreateObjectV3Response
 */
export class ValidationObjectEzsigndocumentCreateObjectV3Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndocumentCreateObjectV3ResponseMPayload()
} 


