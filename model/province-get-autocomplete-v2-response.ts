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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { ProvinceGetAutocompleteV2ResponseMPayload } from './province-get-autocomplete-v2-response-mpayload';

/**
 * @type ProvinceGetAutocompleteV2Response
 * Response for GET /2/object/province/getAutocomplete
 * @export
 */
/*export type ProvinceGetAutocompleteV2Response = CommonResponse;*/
export interface ProvinceGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ProvinceGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ProvinceGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ProvinceGetAutocompleteV2ResponseMPayload}
     * @memberof ProvinceGetAutocompleteV2Response
     */
    mPayload:ProvinceGetAutocompleteV2ResponseMPayload 
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
import { DataObjectProvinceGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectProvinceGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A ProvinceGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectProvinceGetAutocompleteV2Response
 */
export class DataObjectProvinceGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ProvinceGetAutocompleteV2ResponseMPayload = new DataObjectProvinceGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A ProvinceGetAutocompleteV2Response Validation Object
 * @class ValidationObjectProvinceGetAutocompleteV2Response
 */
export class ValidationObjectProvinceGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectProvinceGetAutocompleteV2ResponseMPayload()
} 


