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
import { EzsigntemplateGetAutocompleteV2ResponseMPayload } from './ezsigntemplate-get-autocomplete-v2-response-mpayload';

/**
 * @type EzsigntemplateGetAutocompleteV2Response
 * Response for GET /2/object/ezsigntemplate/getAutocomplete
 * @export
 */
/*export type EzsigntemplateGetAutocompleteV2Response = CommonResponse;*/
export interface EzsigntemplateGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplateGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplateGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplateGetAutocompleteV2ResponseMPayload}
     * @memberof EzsigntemplateGetAutocompleteV2Response
     */
    mPayload:EzsigntemplateGetAutocompleteV2ResponseMPayload 
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
import { DataObjectEzsigntemplateGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplateGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateGetAutocompleteV2Response
 */
export class DataObjectEzsigntemplateGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplateGetAutocompleteV2ResponseMPayload = new DataObjectEzsigntemplateGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplateGetAutocompleteV2Response Validation Object
 * @class ValidationObjectEzsigntemplateGetAutocompleteV2Response
 */
export class ValidationObjectEzsigntemplateGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplateGetAutocompleteV2ResponseMPayload()
} 


