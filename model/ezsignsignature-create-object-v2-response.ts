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
import { EzsignsignatureCreateObjectV2ResponseMPayload } from './ezsignsignature-create-object-v2-response-mpayload';

/**
 * @type EzsignsignatureCreateObjectV2Response
 * Response for POST /2/object/ezsignsignature
 * @export
 */
/*export type EzsignsignatureCreateObjectV2Response = CommonResponse;*/
export interface EzsignsignatureCreateObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsignatureCreateObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsignatureCreateObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsignatureCreateObjectV2ResponseMPayload}
     * @memberof EzsignsignatureCreateObjectV2Response
     */
    mPayload:EzsignsignatureCreateObjectV2ResponseMPayload 
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
import { DataObjectEzsignsignatureCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureCreateObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignatureCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureCreateObjectV2Response
 */
export class DataObjectEzsignsignatureCreateObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsignatureCreateObjectV2ResponseMPayload = new DataObjectEzsignsignatureCreateObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignatureCreateObjectV2Response Validation Object
 * @class ValidationObjectEzsignsignatureCreateObjectV2Response
 */
export class ValidationObjectEzsignsignatureCreateObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsignatureCreateObjectV2ResponseMPayload()
} 


