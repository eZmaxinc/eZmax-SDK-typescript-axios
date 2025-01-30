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
import type { PdfalevelGetAutocompleteV2ResponseMPayload } from './pdfalevel-get-autocomplete-v2-response-mpayload';

/**
 * @type PdfalevelGetAutocompleteV2Response
 * Response for GET /2/object/pdfalevel/getAutocomplete
 * @export
 */
/*export type PdfalevelGetAutocompleteV2Response = CommonResponse;*/
export interface PdfalevelGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof PdfalevelGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof PdfalevelGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {PdfalevelGetAutocompleteV2ResponseMPayload}
     * @memberof PdfalevelGetAutocompleteV2Response
     */
    mPayload:PdfalevelGetAutocompleteV2ResponseMPayload 
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
import { DataObjectPdfalevelGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectPdfalevelGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A PdfalevelGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPdfalevelGetAutocompleteV2Response
 */
export class DataObjectPdfalevelGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:PdfalevelGetAutocompleteV2ResponseMPayload = new DataObjectPdfalevelGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A PdfalevelGetAutocompleteV2Response Validation Object
 * @class ValidationObjectPdfalevelGetAutocompleteV2Response
 */
export class ValidationObjectPdfalevelGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectPdfalevelGetAutocompleteV2ResponseMPayload()
} 


