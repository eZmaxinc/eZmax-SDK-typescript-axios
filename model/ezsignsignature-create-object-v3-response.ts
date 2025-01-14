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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureCreateObjectV3ResponseMPayload } from './ezsignsignature-create-object-v3-response-mpayload';

/**
 * @type EzsignsignatureCreateObjectV3Response
 * Response for POST /3/object/ezsignsignature
 * @export
 */
/*export type EzsignsignatureCreateObjectV3Response = CommonResponse;*/
export interface EzsignsignatureCreateObjectV3Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsignatureCreateObjectV3Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsignatureCreateObjectV3Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsignatureCreateObjectV3ResponseMPayload}
     * @memberof EzsignsignatureCreateObjectV3Response
     */
    mPayload:EzsignsignatureCreateObjectV3ResponseMPayload 
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
import { DataObjectEzsignsignatureCreateObjectV3ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureCreateObjectV3ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignatureCreateObjectV3Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureCreateObjectV3Response
 */
export class DataObjectEzsignsignatureCreateObjectV3Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsignatureCreateObjectV3ResponseMPayload = new DataObjectEzsignsignatureCreateObjectV3ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignatureCreateObjectV3Response Validation Object
 * @class ValidationObjectEzsignsignatureCreateObjectV3Response
 */
export class ValidationObjectEzsignsignatureCreateObjectV3Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsignatureCreateObjectV3ResponseMPayload()
} 


