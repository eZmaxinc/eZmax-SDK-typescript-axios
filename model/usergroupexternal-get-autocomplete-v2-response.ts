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
import type { UsergroupexternalGetAutocompleteV2ResponseMPayload } from './usergroupexternal-get-autocomplete-v2-response-mpayload';

/**
 * @type UsergroupexternalGetAutocompleteV2Response
 * Response for GET /2/object/usergroupexternal/getAutocomplete
 * @export
 */
/*export type UsergroupexternalGetAutocompleteV2Response = CommonResponse;*/
export interface UsergroupexternalGetAutocompleteV2Response {
    /**
     * 
     * @type {UsergroupexternalGetAutocompleteV2ResponseMPayload}
     * @memberof UsergroupexternalGetAutocompleteV2Response
     */
    mPayload:UsergroupexternalGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupexternalGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupexternalGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupexternalGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetAutocompleteV2Response
 */
export class DataObjectUsergroupexternalGetAutocompleteV2Response {
    mPayload:UsergroupexternalGetAutocompleteV2ResponseMPayload = new DataObjectUsergroupexternalGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A UsergroupexternalGetAutocompleteV2Response Validation Object
 * @class ValidationObjectUsergroupexternalGetAutocompleteV2Response
 */
export class ValidationObjectUsergroupexternalGetAutocompleteV2Response {
   mPayload = new ValidationObjectUsergroupexternalGetAutocompleteV2ResponseMPayload()
} 


