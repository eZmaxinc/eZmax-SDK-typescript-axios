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
import { SupplyGetAutocompleteV2ResponseMPayload } from './supply-get-autocomplete-v2-response-mpayload';

/**
 * @type SupplyGetAutocompleteV2Response
 * Response for GET /2/object/supply/getAutocomplete
 * @export
 */
/*export type SupplyGetAutocompleteV2Response = CommonResponse;*/
export interface SupplyGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof SupplyGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof SupplyGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {SupplyGetAutocompleteV2ResponseMPayload}
     * @memberof SupplyGetAutocompleteV2Response
     */
    mPayload:SupplyGetAutocompleteV2ResponseMPayload 
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
import { DataObjectSupplyGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectSupplyGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A SupplyGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSupplyGetAutocompleteV2Response
 */
export class DataObjectSupplyGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:SupplyGetAutocompleteV2ResponseMPayload = new DataObjectSupplyGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A SupplyGetAutocompleteV2Response Validation Object
 * @class ValidationObjectSupplyGetAutocompleteV2Response
 */
export class ValidationObjectSupplyGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectSupplyGetAutocompleteV2ResponseMPayload()
} 


