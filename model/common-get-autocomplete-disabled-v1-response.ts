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
import { CommonGetAutocompleteDisabledV1ResponseAllOf } from './common-get-autocomplete-disabled-v1-response-all-of';
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
import { CustomAutocompleteElementDisabledResponse } from './custom-autocomplete-element-disabled-response';

import { DefaultObject } from '../base'

/**
 * @type CommonGetAutocompleteDisabledV1Response
 * Response for GET /1/object/xxx/getAutocomplete with a bDisabled Flag
 * @export
 */
export type CommonGetAutocompleteDisabledV1Response = CommonGetAutocompleteDisabledV1ResponseAllOf & CommonResponse;


/**
 * @export 
 * A CommonGetAutocompleteDisabledV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectCommonGetAutocompleteDisabledV1Response
 */
export class DefaultObjectCommonGetAutocompleteDisabledV1Response extends DefaultObject {
   mPayload:Array<CustomAutocompleteElementDisabledResponse> = []
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


