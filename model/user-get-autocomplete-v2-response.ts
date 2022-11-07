/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
import { UserGetAutocompleteV2ResponseAllOf } from './user-get-autocomplete-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { UserGetAutocompleteV2ResponseMPayload } from './user-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type UserGetAutocompleteV2Response
 * Response for GET /2/object/user/getAutocomplete
 * @export
 */
export type UserGetAutocompleteV2Response = CommonResponse & UserGetAutocompleteV2ResponseAllOf;


/**
 * @export 
 * A UserGetAutocompleteV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectUserGetAutocompleteV2Response
 */
export class DefaultObjectUserGetAutocompleteV2Response extends DefaultObject {
   mPayload:Partial<UserGetAutocompleteV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


