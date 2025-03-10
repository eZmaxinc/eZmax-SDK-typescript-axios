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
import type { VariableexpenseGetObjectV2ResponseMPayload } from './variableexpense-get-object-v2-response-mpayload';

/**
 * @type VariableexpenseGetObjectV2Response
 * Response for GET /2/object/variableexpense/{pkiVariableexpenseID}
 * @export
 */
/*export type VariableexpenseGetObjectV2Response = CommonResponse;*/
export interface VariableexpenseGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof VariableexpenseGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof VariableexpenseGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {VariableexpenseGetObjectV2ResponseMPayload}
     * @memberof VariableexpenseGetObjectV2Response
     */
    mPayload:VariableexpenseGetObjectV2ResponseMPayload 
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
import { DataObjectVariableexpenseGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectVariableexpenseGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A VariableexpenseGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseGetObjectV2Response
 */
export class DataObjectVariableexpenseGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:VariableexpenseGetObjectV2ResponseMPayload = new DataObjectVariableexpenseGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A VariableexpenseGetObjectV2Response Validation Object
 * @class ValidationObjectVariableexpenseGetObjectV2Response
 */
export class ValidationObjectVariableexpenseGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectVariableexpenseGetObjectV2ResponseMPayload()
} 


