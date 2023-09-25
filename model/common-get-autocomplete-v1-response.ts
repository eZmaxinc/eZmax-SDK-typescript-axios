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
import { CustomAutocompleteElementResponse } from './custom-autocomplete-element-response';

/**
 * @type CommonGetAutocompleteV1Response
 * Response for GET /1/object/xxx/getAutocomplete
 * @export
 */
/** export type CommonGetAutocompleteV1Response = CommonResponse; */
export interface CommonGetAutocompleteV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CommonGetAutocompleteV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CommonGetAutocompleteV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * Generic Autocomplete Response
     * @type {Array<CustomAutocompleteElementResponse>}
     * @memberof CommonGetAutocompleteV1Response
     */
    mPayload:Array<CustomAutocompleteElementResponse> 
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
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A CommonGetAutocompleteV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonGetAutocompleteV1Response
 */
export class DataObjectCommonGetAutocompleteV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:Array<CustomAutocompleteElementResponse> = []
}

/**
 * @export 
 * A CommonGetAutocompleteV1Response Validation Object
 * @class ValidationObjectCommonGetAutocompleteV1Response
 */
export class ValidationObjectCommonGetAutocompleteV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = {
      type: 'array',
      required: true
   }
} 


