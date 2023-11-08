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
import { EzmaxproductGetAutocompleteV2ResponseMPayload } from './ezmaxproduct-get-autocomplete-v2-response-mpayload';

/**
 * @type EzmaxproductGetAutocompleteV2Response
 * Response for GET /2/object/ezmaxproduct/getAutocomplete
 * @export
 */
/** export type EzmaxproductGetAutocompleteV2Response = CommonResponse; */
export interface EzmaxproductGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzmaxproductGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzmaxproductGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzmaxproductGetAutocompleteV2ResponseMPayload}
     * @memberof EzmaxproductGetAutocompleteV2Response
     */
    mPayload:EzmaxproductGetAutocompleteV2ResponseMPayload 
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
import { DataObjectEzmaxproductGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzmaxproductGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A EzmaxproductGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxproductGetAutocompleteV2Response
 */
export class DataObjectEzmaxproductGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzmaxproductGetAutocompleteV2ResponseMPayload = new DataObjectEzmaxproductGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A EzmaxproductGetAutocompleteV2Response Validation Object
 * @class ValidationObjectEzmaxproductGetAutocompleteV2Response
 */
export class ValidationObjectEzmaxproductGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzmaxproductGetAutocompleteV2ResponseMPayload()
} 

