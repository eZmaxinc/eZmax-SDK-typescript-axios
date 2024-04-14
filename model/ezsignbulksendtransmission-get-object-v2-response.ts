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
import { EzsignbulksendtransmissionGetObjectV2ResponseMPayload } from './ezsignbulksendtransmission-get-object-v2-response-mpayload';

/**
 * @type EzsignbulksendtransmissionGetObjectV2Response
 * Response for GET /2/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}
 * @export
 */
/*export type EzsignbulksendtransmissionGetObjectV2Response = CommonResponse;*/
export interface EzsignbulksendtransmissionGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendtransmissionGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendtransmissionGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendtransmissionGetObjectV2ResponseMPayload}
     * @memberof EzsignbulksendtransmissionGetObjectV2Response
     */
    mPayload:EzsignbulksendtransmissionGetObjectV2ResponseMPayload 
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
import { DataObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetObjectV2Response
 */
export class DataObjectEzsignbulksendtransmissionGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendtransmissionGetObjectV2ResponseMPayload = new DataObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetObjectV2Response
 */
export class ValidationObjectEzsignbulksendtransmissionGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload()
} 


