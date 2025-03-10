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
import type { EzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload } from './ezsignbulksend-create-ezsignbulksendtransmission-v2-response-mpayload';

/**
 * @type EzsignbulksendCreateEzsignbulksendtransmissionV2Response
 * Response for POST /2/object/ezsignbulksend/{pkiEzsignbulksendID}/createEzsignbulksendtransmission
 * @export
 */
/*export type EzsignbulksendCreateEzsignbulksendtransmissionV2Response = CommonResponse;*/
export interface EzsignbulksendCreateEzsignbulksendtransmissionV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV2Response
     */
    mPayload:EzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload 
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
import { DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendCreateEzsignbulksendtransmissionV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV2Response
 */
export class DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload = new DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendCreateEzsignbulksendtransmissionV2Response Validation Object
 * @class ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV2Response
 */
export class ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV2ResponseMPayload()
} 


