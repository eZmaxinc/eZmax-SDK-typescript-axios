/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { FranchisereferalincomeCreateObjectV2ResponseAllOf } from './franchisereferalincome-create-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeCreateObjectV2ResponseMPayload } from './franchisereferalincome-create-object-v2-response-mpayload';

/**
 * @type FranchisereferalincomeCreateObjectV2Response
 * Response for POST /2/object/franchisereferalincome
 * @export
 */
export type FranchisereferalincomeCreateObjectV2Response = CommonResponse & FranchisereferalincomeCreateObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectFranchisereferalincomeCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectFranchisereferalincomeCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A FranchisereferalincomeCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchisereferalincomeCreateObjectV2Response
 */
export class DataObjectFranchisereferalincomeCreateObjectV2Response {
   mPayload:FranchisereferalincomeCreateObjectV2ResponseMPayload = new DataObjectFranchisereferalincomeCreateObjectV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A FranchisereferalincomeCreateObjectV2Response Validation Object
 * @class ValidationObjectFranchisereferalincomeCreateObjectV2Response
 */
export class ValidationObjectFranchisereferalincomeCreateObjectV2Response {
   mPayload = new ValidationObjectFranchisereferalincomeCreateObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


