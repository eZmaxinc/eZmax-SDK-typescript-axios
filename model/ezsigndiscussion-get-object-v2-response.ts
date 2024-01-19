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
import { EzsigndiscussionGetObjectV2ResponseMPayload } from './ezsigndiscussion-get-object-v2-response-mpayload';

/**
 * @type EzsigndiscussionGetObjectV2Response
 * Response for GET /2/object/ezsigndiscussion/{pkiEzsigndiscussionID}
 * @export
 */
/** export type EzsigndiscussionGetObjectV2Response = CommonResponse; */
export interface EzsigndiscussionGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndiscussionGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndiscussionGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndiscussionGetObjectV2ResponseMPayload}
     * @memberof EzsigndiscussionGetObjectV2Response
     */
    mPayload:EzsigndiscussionGetObjectV2ResponseMPayload 
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
import { DataObjectEzsigndiscussionGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndiscussionGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndiscussionGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndiscussionGetObjectV2Response
 */
export class DataObjectEzsigndiscussionGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndiscussionGetObjectV2ResponseMPayload = new DataObjectEzsigndiscussionGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigndiscussionGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigndiscussionGetObjectV2Response
 */
export class ValidationObjectEzsigndiscussionGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndiscussionGetObjectV2ResponseMPayload()
} 


