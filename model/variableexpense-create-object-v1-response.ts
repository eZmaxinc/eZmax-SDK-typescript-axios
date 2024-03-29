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
// May contain unused imports in some cases
// @ts-ignore
import { VariableexpenseCreateObjectV1ResponseAllOf } from './variableexpense-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { VariableexpenseCreateObjectV1ResponseMPayload } from './variableexpense-create-object-v1-response-mpayload';

/**
 * @type VariableexpenseCreateObjectV1Response
 * Response for POST /1/object/variableexpense
 * @export
 */
export type VariableexpenseCreateObjectV1Response = CommonResponse & VariableexpenseCreateObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectVariableexpenseCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectVariableexpenseCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A VariableexpenseCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseCreateObjectV1Response
 */
export class DataObjectVariableexpenseCreateObjectV1Response {
    mPayload:VariableexpenseCreateObjectV1ResponseMPayload = new DataObjectVariableexpenseCreateObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A VariableexpenseCreateObjectV1Response Validation Object
 * @class ValidationObjectVariableexpenseCreateObjectV1Response
 */
export class ValidationObjectVariableexpenseCreateObjectV1Response {
   mPayload = new ValidationObjectVariableexpenseCreateObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


