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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { VariableexpenseGetListV1ResponseAllOf } from './variableexpense-get-list-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { VariableexpenseGetListV1ResponseMPayload } from './variableexpense-get-list-v1-response-mpayload';

/**
 * @type VariableexpenseGetListV1Response
 * Response for GET /1/object/variableexpense/getList
 * @export
 */
export type VariableexpenseGetListV1Response = CommonResponseGetList & VariableexpenseGetListV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectVariableexpenseGetListV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectVariableexpenseGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A VariableexpenseGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseGetListV1Response
 */
export class DataObjectVariableexpenseGetListV1Response {
    mPayload:VariableexpenseGetListV1ResponseMPayload = new DataObjectVariableexpenseGetListV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayloadGetList = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A VariableexpenseGetListV1Response Validation Object
 * @class ValidationObjectVariableexpenseGetListV1Response
 */
export class ValidationObjectVariableexpenseGetListV1Response {
   mPayload = new ValidationObjectVariableexpenseGetListV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


