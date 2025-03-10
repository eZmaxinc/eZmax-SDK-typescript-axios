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
import type { EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './ezsignbulksendtransmission-get-forms-data-v1-response-mpayload';

/**
 * @type EzsignbulksendtransmissionGetFormsDataV1Response
 * Response for GET /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getFormsData
 * @export
 */
/*export type EzsignbulksendtransmissionGetFormsDataV1Response = CommonResponse;*/
export interface EzsignbulksendtransmissionGetFormsDataV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendtransmissionGetFormsDataV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendtransmissionGetFormsDataV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload}
     * @memberof EzsignbulksendtransmissionGetFormsDataV1Response
     */
    mPayload:EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload 
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
import { DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetFormsDataV1Response
 */
export class DataObjectEzsignbulksendtransmissionGetFormsDataV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload = new DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1Response Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetFormsDataV1Response
 */
export class ValidationObjectEzsignbulksendtransmissionGetFormsDataV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload()
} 


