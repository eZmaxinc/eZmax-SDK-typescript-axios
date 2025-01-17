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
import type { LanguageGetAutocompleteV2ResponseMPayload } from './language-get-autocomplete-v2-response-mpayload';

/**
 * @type LanguageGetAutocompleteV2Response
 * Response for GET /2/object/language/getAutocomplete
 * @export
 */
/*export type LanguageGetAutocompleteV2Response = CommonResponse;*/
export interface LanguageGetAutocompleteV2Response {
    /**
     * 
     * @type {LanguageGetAutocompleteV2ResponseMPayload}
     * @memberof LanguageGetAutocompleteV2Response
     */
    mPayload:LanguageGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectLanguageGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectLanguageGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A LanguageGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectLanguageGetAutocompleteV2Response
 */
export class DataObjectLanguageGetAutocompleteV2Response {
    mPayload:LanguageGetAutocompleteV2ResponseMPayload = new DataObjectLanguageGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A LanguageGetAutocompleteV2Response Validation Object
 * @class ValidationObjectLanguageGetAutocompleteV2Response
 */
export class ValidationObjectLanguageGetAutocompleteV2Response {
   mPayload = new ValidationObjectLanguageGetAutocompleteV2ResponseMPayload()
} 


