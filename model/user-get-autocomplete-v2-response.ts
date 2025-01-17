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
import type { UserGetAutocompleteV2ResponseMPayload } from './user-get-autocomplete-v2-response-mpayload';

/**
 * @type UserGetAutocompleteV2Response
 * Response for GET /2/object/user/getAutocomplete
 * @export
 */
/*export type UserGetAutocompleteV2Response = CommonResponse;*/
export interface UserGetAutocompleteV2Response {
    /**
     * 
     * @type {UserGetAutocompleteV2ResponseMPayload}
     * @memberof UserGetAutocompleteV2Response
     */
    mPayload:UserGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A UserGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetAutocompleteV2Response
 */
export class DataObjectUserGetAutocompleteV2Response {
    mPayload:UserGetAutocompleteV2ResponseMPayload = new DataObjectUserGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A UserGetAutocompleteV2Response Validation Object
 * @class ValidationObjectUserGetAutocompleteV2Response
 */
export class ValidationObjectUserGetAutocompleteV2Response {
   mPayload = new ValidationObjectUserGetAutocompleteV2ResponseMPayload()
} 


