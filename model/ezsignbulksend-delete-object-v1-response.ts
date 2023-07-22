/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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

/**
 * @type EzsignbulksendDeleteObjectV1Response
 * Response for DELETE /1/object/ezsignbulksend/{pkiEzsignbulksendID}
 * @export
 */
export type EzsignbulksendDeleteObjectV1Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignbulksendDeleteObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendDeleteObjectV1Response
 */
export class DataObjectEzsignbulksendDeleteObjectV1Response {
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignbulksendDeleteObjectV1Response Validation Object
 * @class ValidationObjectEzsignbulksendDeleteObjectV1Response
 */
export class ValidationObjectEzsignbulksendDeleteObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


