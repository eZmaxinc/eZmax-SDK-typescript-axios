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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { DepartmentGetAutocompleteV2ResponseMPayload } from './department-get-autocomplete-v2-response-mpayload';

/**
 * @type DepartmentGetAutocompleteV2Response
 * Response for GET /2/object/department/getAutocomplete
 * @export
 */
/*export type DepartmentGetAutocompleteV2Response = CommonResponse;*/
export interface DepartmentGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof DepartmentGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof DepartmentGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {DepartmentGetAutocompleteV2ResponseMPayload}
     * @memberof DepartmentGetAutocompleteV2Response
     */
    mPayload:DepartmentGetAutocompleteV2ResponseMPayload 
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
import { DataObjectDepartmentGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectDepartmentGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A DepartmentGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDepartmentGetAutocompleteV2Response
 */
export class DataObjectDepartmentGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:DepartmentGetAutocompleteV2ResponseMPayload = new DataObjectDepartmentGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A DepartmentGetAutocompleteV2Response Validation Object
 * @class ValidationObjectDepartmentGetAutocompleteV2Response
 */
export class ValidationObjectDepartmentGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectDepartmentGetAutocompleteV2ResponseMPayload()
} 


