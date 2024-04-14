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
import { EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload } from './ezsignbulksend-create-ezsignbulksendtransmission-v1-response-mpayload';

/**
 * @type EzsignbulksendCreateEzsignbulksendtransmissionV1Response
 * Response for POST /1/object/ezsignbulksend/{pkiEzsignbulksendID}/createEzsignbulksendtransmission
 * @export
 */
/*export type EzsignbulksendCreateEzsignbulksendtransmissionV1Response = CommonResponse;*/
export interface EzsignbulksendCreateEzsignbulksendtransmissionV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV1Response
     */
    mPayload:EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload 
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
import { DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendCreateEzsignbulksendtransmissionV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV1Response
 */
export class DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload = new DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendCreateEzsignbulksendtransmissionV1Response Validation Object
 * @class ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV1Response
 */
export class ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload()
} 


