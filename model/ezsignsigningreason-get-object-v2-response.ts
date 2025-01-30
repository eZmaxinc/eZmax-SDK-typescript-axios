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
import type { EzsignsigningreasonGetObjectV2ResponseMPayload } from './ezsignsigningreason-get-object-v2-response-mpayload';

/**
 * @type EzsignsigningreasonGetObjectV2Response
 * Response for GET /2/object/ezsignsigningreason/{pkiEzsignsigningreasonID}
 * @export
 */
/*export type EzsignsigningreasonGetObjectV2Response = CommonResponse;*/
export interface EzsignsigningreasonGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsigningreasonGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsigningreasonGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsigningreasonGetObjectV2ResponseMPayload}
     * @memberof EzsignsigningreasonGetObjectV2Response
     */
    mPayload:EzsignsigningreasonGetObjectV2ResponseMPayload 
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
import { DataObjectEzsignsigningreasonGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsigningreasonGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsigningreasonGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonGetObjectV2Response
 */
export class DataObjectEzsignsigningreasonGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsigningreasonGetObjectV2ResponseMPayload = new DataObjectEzsignsigningreasonGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignsigningreasonGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignsigningreasonGetObjectV2Response
 */
export class ValidationObjectEzsignsigningreasonGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsigningreasonGetObjectV2ResponseMPayload()
} 


