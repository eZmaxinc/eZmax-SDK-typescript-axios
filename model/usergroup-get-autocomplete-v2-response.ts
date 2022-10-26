/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
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
import { UsergroupGetAutocompleteV2ResponseAllOf } from './usergroup-get-autocomplete-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupGetAutocompleteV2ResponseMPayload } from './usergroup-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type UsergroupGetAutocompleteV2Response
 * Response for GET /2/object/usergroup/getAutocomplete
 * @export
 */
export type UsergroupGetAutocompleteV2Response = CommonResponse & UsergroupGetAutocompleteV2ResponseAllOf;


/**
 * @export 
 * A UsergroupGetAutocompleteV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectUsergroupGetAutocompleteV2Response
 */
export class DefaultObjectUsergroupGetAutocompleteV2Response extends DefaultObject {
   mPayload:Partial<UsergroupGetAutocompleteV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


