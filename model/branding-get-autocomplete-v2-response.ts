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
import { BrandingGetAutocompleteV2ResponseAllOf } from './branding-get-autocomplete-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { BrandingGetAutocompleteV2ResponseMPayload } from './branding-get-autocomplete-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

import { DefaultObject } from '../base'

/**
 * @type BrandingGetAutocompleteV2Response
 * Response for GET /2/object/branding/getAutocomplete
 * @export
 */
export type BrandingGetAutocompleteV2Response = BrandingGetAutocompleteV2ResponseAllOf & CommonResponse;


/**
 * @export 
 * A BrandingGetAutocompleteV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectBrandingGetAutocompleteV2Response
 */
export class DefaultObjectBrandingGetAutocompleteV2Response extends DefaultObject {
   mPayload:Partial<BrandingGetAutocompleteV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


