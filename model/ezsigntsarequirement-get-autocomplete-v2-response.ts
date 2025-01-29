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
import type { EzsigntsarequirementGetAutocompleteV2ResponseMPayload } from './ezsigntsarequirement-get-autocomplete-v2-response-mpayload';

/**
 * @type EzsigntsarequirementGetAutocompleteV2Response
 * Response for GET /2/object/ezsigntsarequirement/getAutocomplete
 * @export
 */
/*export type EzsigntsarequirementGetAutocompleteV2Response = CommonResponse;*/
export interface EzsigntsarequirementGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntsarequirementGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntsarequirementGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntsarequirementGetAutocompleteV2ResponseMPayload}
     * @memberof EzsigntsarequirementGetAutocompleteV2Response
     */
    mPayload:EzsigntsarequirementGetAutocompleteV2ResponseMPayload 
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
import { DataObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntsarequirementGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntsarequirementGetAutocompleteV2Response
 */
export class DataObjectEzsigntsarequirementGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntsarequirementGetAutocompleteV2ResponseMPayload = new DataObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntsarequirementGetAutocompleteV2Response Validation Object
 * @class ValidationObjectEzsigntsarequirementGetAutocompleteV2Response
 */
export class ValidationObjectEzsigntsarequirementGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntsarequirementGetAutocompleteV2ResponseMPayload()
} 


