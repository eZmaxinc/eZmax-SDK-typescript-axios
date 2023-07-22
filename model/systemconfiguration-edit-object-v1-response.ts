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
 * @type SystemconfigurationEditObjectV1Response
 * Response for PUT /1/object/systemconfiguration/{pkiSystemconfigurationID}
 * @export
 */
export type SystemconfigurationEditObjectV1Response = CommonResponse;


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
 * A SystemconfigurationEditObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSystemconfigurationEditObjectV1Response
 */
export class DataObjectSystemconfigurationEditObjectV1Response {
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A SystemconfigurationEditObjectV1Response Validation Object
 * @class ValidationObjectSystemconfigurationEditObjectV1Response
 */
export class ValidationObjectSystemconfigurationEditObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


