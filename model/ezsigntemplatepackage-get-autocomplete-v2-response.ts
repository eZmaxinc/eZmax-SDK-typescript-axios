/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsigntemplatepackageGetAutocompleteV2ResponseAllOf } from './ezsigntemplatepackage-get-autocomplete-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageGetAutocompleteV2ResponseMPayload } from './ezsigntemplatepackage-get-autocomplete-v2-response-mpayload';

/**
 * @type EzsigntemplatepackageGetAutocompleteV2Response
 * Response for GET /2/object/ezsigntemplatepackage/getAutocomplete
 * @export
 */
export type EzsigntemplatepackageGetAutocompleteV2Response = CommonResponse & EzsigntemplatepackageGetAutocompleteV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigntemplatepackageGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageGetAutocompleteV2Response
 */
export class DataObjectEzsigntemplatepackageGetAutocompleteV2Response {
   mPayload:EzsigntemplatepackageGetAutocompleteV2ResponseMPayload = new DataObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplatepackageGetAutocompleteV2Response Validation Object
 * @class ValidationObjectEzsigntemplatepackageGetAutocompleteV2Response
 */
export class ValidationObjectEzsigntemplatepackageGetAutocompleteV2Response {
   mPayload = new ValidationObjectEzsigntemplatepackageGetAutocompleteV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


