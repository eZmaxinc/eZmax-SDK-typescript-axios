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
import { PhonetypeGetAutocompleteV2ResponseMPayload } from './phonetype-get-autocomplete-v2-response-mpayload';

/**
 * @type PhonetypeGetAutocompleteV2Response
 * Response for GET /2/object/phonetype/getAutocomplete
 * @export
 */
/** export type PhonetypeGetAutocompleteV2Response = CommonResponse; */
export interface PhonetypeGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof PhonetypeGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof PhonetypeGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {PhonetypeGetAutocompleteV2ResponseMPayload}
     * @memberof PhonetypeGetAutocompleteV2Response
     */
    mPayload:PhonetypeGetAutocompleteV2ResponseMPayload 
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
import { DataObjectPhonetypeGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectPhonetypeGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A PhonetypeGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhonetypeGetAutocompleteV2Response
 */
export class DataObjectPhonetypeGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:PhonetypeGetAutocompleteV2ResponseMPayload = new DataObjectPhonetypeGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A PhonetypeGetAutocompleteV2Response Validation Object
 * @class ValidationObjectPhonetypeGetAutocompleteV2Response
 */
export class ValidationObjectPhonetypeGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectPhonetypeGetAutocompleteV2ResponseMPayload()
} 

